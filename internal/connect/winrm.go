// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway/winrmgw"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/protocol"
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
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", "ticket is not for winrm")
		return
	}
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))

	ep, err := h.resolveGrant(r.Context(), g)
	if err != nil || !ep.Active {
		httpx.WriteError(w, r, http.StatusConflict, "target_unavailable", "target is no longer available")
		return
	}
	// WinRM dials before the upgrade, so its address is checked here, before
	// the credential is opened, and the client dials the checked address.
	dialIP, err := h.checkAddress(r, g, ep)
	if err != nil {
		refuseAddress(w, r, err)
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
			httpx.WriteError(w, r, http.StatusConflict, "credential_unavailable", "credential could not be opened")
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
		httpx.WriteError(w, r, http.StatusConflict, "certificate_unpinned", "winrm target is not pinned; probe it over HTTPS first")
		return
	}
	client, err := winrmgw.Dial(r.Context(), winrmgw.Endpoint{Address: ep.Address, IP: dialIP.String(), Port: port, UseTLS: true, PinnedFingerprint: ep.WinRMTLSFingerprint}, a, timeout)
	if err != nil {
		if errors.Is(err, winrmgw.ErrCertMismatch) {
			h.record(r, actorFor(g.UserID, ip).Event(audit.TargetTLSMismatch, "target", ep.LiveKey, audit.Failure, map[string]string{"protocol": protocol.WinRM, "expected": ep.WinRMTLSFingerprint}))
			httpx.WriteError(w, r, http.StatusConflict, "certificate_mismatch", "the target presented a different certificate; connection refused")
			return
		}
		if errors.Is(err, winrmgw.ErrNotAuthorized) {
			h.Log.Warn("winrm authorization refused", "target", ep.LiveKey, "err", err)
			httpx.WriteError(w, r, http.StatusConflict, "not_authorized", winrmAdminHint)
			return
		}
		h.Log.Warn("winrm dial failed", "target", ep.LiveKey, "err", err)
		httpx.WriteError(w, r, http.StatusConflict, "target_unavailable", "could not connect to the target")
		return
	}
	sh, err := client.Shell(r.Context())
	if err != nil {
		h.Log.Warn("winrm shell failed", "target", ep.LiveKey, "err", err)
		if errors.Is(err, winrmgw.ErrNotAuthorized) {
			httpx.WriteError(w, r, http.StatusConflict, "not_authorized", winrmAdminHint)
			return
		}
		httpx.WriteError(w, r, http.StatusConflict, "target_unavailable", "could not open a shell on the target")
		return
	}
	defer func() { _ = sh.Close() }()

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(1 << 20)

	run, ok := h.startRun(r, ws, g, ep, ip)
	if !ok {
		return
	}
	rec, recRow, ok := run.asciicast(sessionLabel(ep), cols, rows)
	if !ok {
		return
	}
	ctx, done := run.live()
	defer done()

	lim := winrmgw.Limits{Idle: g.IdleTimeout, Max: g.MaxSession, SessionID: run.s.ID}
	// The registry's tap feeds shadowing watchers (ADR 0006); see terminal.
	if tap := h.Registry.Tap(run.s.ID); tap != nil {
		lim.Tap = tap
	}
	reason, berr := winrmgw.Bridge(ctx, h.Log, sh, ws, rec, cols, rows, lim)
	run.finish(rec, recRow, reason, berr)
}
