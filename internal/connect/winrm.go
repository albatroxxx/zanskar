// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
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

// winrm redeems a ticket and runs a WinRM PowerShell console for its lifetime.
// Route: GET /ws/winrm?ticket=...&cols=&rows=
//
// WinRM is a line-oriented console, not a raw PTY (see internal/gateway/winrmgw).
// TLS to the target currently trusts the server certificate without pinning; a
// pinned-CA mode is a planned follow-up, mirroring RDP certificate pinning.
func (h *Handler) winrm(w http.ResponseWriter, r *http.Request) {
	ip := auth.ClientIP(r)
	g, err := h.Tickets.Redeem(r.URL.Query().Get("ticket"), ip)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_ticket", "invalid or expired ticket")
		return
	}
	defer zero(g.UserSecret)
	if target.Protocol(g.Protocol) != target.WinRM {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "ticket is not for winrm")
		return
	}
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))

	t, err := h.Targets.Get(r.Context(), g.TargetID)
	if err != nil || t.Status != "active" {
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
	port := t.Port(target.WinRM)
	client, err := winrmgw.Dial(r.Context(), winrmgw.Endpoint{Address: t.Address, Port: port, UseTLS: port != 5985, Insecure: true}, a, timeout)
	if err != nil {
		h.Log.Warn("winrm dial failed", "target", t.ID, "err", err)
		// Persist a stub session so the failure is auditable, then report.
		httpx.WriteError(w, http.StatusConflict, "target_unavailable", "could not connect to the target")
		return
	}
	sh, err := client.Shell(r.Context())
	if err != nil {
		h.Log.Warn("winrm shell failed", "target", t.ID, "err", err)
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

	s := &session.Session{UserID: g.UserID, PolicyID: g.PolicyID, TargetID: t.ID, Protocol: g.Protocol, CredentialID: g.CredentialID, ClientIP: ip, UserAgent: r.UserAgent()}
	if err := h.Sessions.Start(r.Context(), s); err != nil {
		h.Log.Error("start session", "err", err)
		_ = ws.Close(websocket.StatusInternalError, "could not start session")
		return
	}
	actor := audit.Actor{UserID: g.UserID, IP: ip}
	endWith := func(reason string) {
		_ = h.Sessions.End(context.Background(), s.ID, reason)
		h.record(r, actor.Event("session.end", "access_session", s.ID, audit.Success, map[string]string{"reason": reason, "target_id": t.ID}))
	}

	rec, uri, err := recording.NewAsciicast(r.Context(), h.Storage, s.ID+".cast", recording.Header{Width: cols, Height: rows, Title: t.Name,
		Env: map[string]string{"ZANSKAR_SESSION": s.ID}})
	if err != nil {
		h.Log.Error("start recording", "err", err)
		endWith(session.EndError)
		_ = ws.Close(websocket.StatusInternalError, "recording could not be started")
		return
	}
	recRow := &session.Recording{SessionID: s.ID, Format: "asciicast", StorageURI: uri}
	if err := h.Sessions.CreateRecording(r.Context(), recRow); err != nil {
		h.Log.Error("register recording", "err", err)
		_, _, _ = rec.Close()
		endWith(session.EndError)
		return
	}
	h.record(r, actor.Event("session.start", "access_session", s.ID, audit.Success, map[string]any{"target_id": t.ID, "protocol": g.Protocol, "policy_id": g.PolicyID, "recording_id": recRow.ID}))

	ctx := h.Registry.Add(r.Context(), gateway.Live{SessionID: s.ID, UserID: g.UserID, TargetID: t.ID, Protocol: g.Protocol})
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
