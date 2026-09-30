// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/winrmgw"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
)

func actorFor(userID, ip string) audit.Actor { return audit.Actor{UserID: userID, IP: ip} }

// winrmAdminHint is the answer to the target refusing a shell to a credential
// it did authenticate. Zanskar runs a WinRS shell, which WinRM's RootSDDL
// grants to local administrators only.
const winrmAdminHint = "the target refused a shell to this credential; a WinRM credential must be a local administrator on the target (Remote Management Users is not enough)"

// winrm redeems a ticket and runs a WinRM PowerShell console for its lifetime.
// Route: GET /ws/winrm?ticket=...&cols=&rows=
//
// WinRM is a line-oriented console, not a raw PTY (see internal/gateway/winrmgw).
// TLS to the target is pinned to the listener certificate captured by the
// probe (mirroring RDP, ADR 0012); plain-HTTP WinRM is refused outright.
func (h *Handler) winrm(w http.ResponseWriter, r *http.Request) {
	ip := auth.ClientIP(r)
	g, ok := h.redeem(w, r)
	if !ok {
		return
	}
	defer zero(g.UserSecret)
	if target.Protocol(g.Protocol) != target.WinRM {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "ticket is not for winrm")
		return
	}
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))

	ep, err := h.resolveGrant(r.Context(), g)
	if err != nil || !ep.Active {
		httpx.WriteError(w, http.StatusConflict, "target_unavailable", "target is no longer available")
		return
	}

	// Resolve credential material before upgrading.
	a := winrmgw.Auth{Username: g.Username}
	if len(g.UserSecret) > 0 {
		a.Password = string(g.UserSecret)
	} else {
		opened, err := h.Vault.Open(r.Context(), g.CredentialID)
		if err != nil {
			h.Log.Error("open credential", "id", g.CredentialID, "err", err)
			httpx.WriteError(w, http.StatusConflict, "credential_unavailable", "credential could not be opened")
			return
		}
		defer opened.Close()
		a.Username, a.Password, a.Domain = opened.Username, opened.Password, opened.Domain
	}

	timeout := h.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	port := ep.port(target.WinRM)
	if port == 5985 || ep.WinRMTLSFingerprint == "" {
		// connect() already refuses these; re-check here because the ticket
		// was issued earlier and the target may have been re-probed since.
		httpx.WriteError(w, http.StatusConflict, "certificate_unpinned", "winrm target is not pinned; probe it over HTTPS first")
		return
	}
	client, err := winrmgw.Dial(r.Context(), winrmgw.Endpoint{Address: ep.Address, Port: port, UseTLS: true, PinnedFingerprint: ep.WinRMTLSFingerprint}, a, timeout)
	if err != nil {
		if errors.Is(err, winrmgw.ErrCertMismatch) {
			h.record(r, actorFor(g.UserID, ip).Event("target.tls.mismatch", "target", ep.LiveKey, audit.Failure, map[string]string{"protocol": "winrm", "expected": ep.WinRMTLSFingerprint}))
			httpx.WriteError(w, http.StatusConflict, "certificate_mismatch", "the target presented a different certificate; connection refused")
			return
		}
		if errors.Is(err, winrmgw.ErrNotAuthorized) {
			h.Log.Warn("winrm authorization refused", "target", ep.LiveKey, "err", err)
			httpx.WriteError(w, http.StatusConflict, "not_authorized", winrmAdminHint)
			return
		}
		h.Log.Warn("winrm dial failed", "target", ep.LiveKey, "err", err)
		httpx.WriteError(w, http.StatusConflict, "target_unavailable", "could not connect to the target")
		return
	}
	sh, err := client.Shell(r.Context())
	if err != nil {
		h.Log.Warn("winrm shell failed", "target", ep.LiveKey, "err", err)
		if errors.Is(err, winrmgw.ErrNotAuthorized) {
			httpx.WriteError(w, http.StatusConflict, "not_authorized", winrmAdminHint)
			return
		}
		httpx.WriteError(w, http.StatusConflict, "target_unavailable", "could not open a shell on the target")
		return
	}
	defer func() { _ = sh.Close() }()

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(1 << 20)

	s := &session.Session{UserID: g.UserID, PolicyID: g.PolicyID, TargetID: ep.TargetID, ASGID: ep.ASGID, ASGInstanceID: ep.ASGInstanceID,
		Protocol: g.Protocol, CredentialID: g.CredentialID, ClientIP: ip, UserAgent: r.UserAgent()}
	if err := h.Sessions.Start(r.Context(), s); err != nil {
		h.Log.Error("start session", "err", err)
		_ = ws.Close(websocket.StatusInternalError, "could not start session")
		return
	}
	actor := audit.Actor{UserID: g.UserID, IP: ip}
	endWith := func(reason string) {
		_ = h.Sessions.End(context.Background(), s.ID, reason)
		h.record(r, actor.Event("session.end", "access_session", s.ID, audit.Success, map[string]string{"reason": reason, "target_id": ep.LiveKey}))
	}

	rec, uri, err := recording.NewAsciicast(r.Context(), h.Storage, s.ID+".cast", recording.Header{Width: cols, Height: rows, Title: sessionLabel(ep),
		Env: map[string]string{"ZANSKAR_SESSION": s.ID}})
	if err != nil {
		h.Log.Error("start recording", "err", err)
		endWith(session.EndError)
		_ = ws.Close(websocket.StatusInternalError, "recording could not be started")
		return
	}
	recRow := &session.Recording{SessionID: s.ID, Format: "asciicast", StorageURI: uri, RetentionUntil: retentionUntil(g)}
	if err := h.Sessions.CreateRecording(r.Context(), recRow); err != nil {
		h.Log.Error("register recording", "err", err)
		_, _, _ = rec.Close()
		endWith(session.EndError)
		return
	}
	h.record(r, actor.Event("session.start", "access_session", s.ID, audit.Success, map[string]any{"target_id": ep.LiveKey, "protocol": g.Protocol, "policy_id": g.PolicyID, "recording_id": recRow.ID}))

	ctx := h.Registry.Add(r.Context(), gateway.Live{SessionID: s.ID, UserID: g.UserID, TargetID: ep.LiveKey, Protocol: g.Protocol})
	defer h.Registry.Remove(s.ID)

	reason, berr := winrmgw.Bridge(ctx, h.Log, sh, ws, rec, cols, rows, winrmgw.Limits{Idle: g.IdleTimeout, Max: g.MaxSession})
	size, sum, cerr := rec.Close()
	if cerr != nil {
		h.Log.Error("close recording", "session", s.ID, "err", cerr)
	}
	if err := h.Sessions.FinishRecording(context.Background(), recRow.ID, size, sum); err != nil {
		h.Log.Error("finish recording", "session", s.ID, "err", err)
	}
	if berr != nil {
		h.Log.Warn("winrm bridge ended with error", "session", s.ID, "err", berr)
	}
	endWith(reason)
	_ = ws.Close(websocket.StatusNormalClosure, reason)
}
