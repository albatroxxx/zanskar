// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"net/http"
	"strconv"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/dbgw"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
)

// database redeems a ticket and runs a brokered database session for its
// lifetime (ADR 0017). dbgw runs the version-matched client in an ephemeral
// container connected to a credential-holding proxy sidecar; the browser sees
// only the terminal, and the credential never reaches the client container.
func (h *Handler) database(w http.ResponseWriter, r *http.Request) {
	ip := auth.ClientIP(r)
	g, err := h.Tickets.Redeem(r.URL.Query().Get("ticket"), ip)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_ticket", "invalid or expired ticket")
		return
	}
	defer zero(g.UserSecret)
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))

	ep, err := h.resolveGrant(r.Context(), g)
	if err != nil || !ep.Active || ep.Engine == "" {
		httpx.WriteError(w, http.StatusConflict, "target_unavailable", "target is no longer available")
		return
	}

	// Resolve the upstream credential before upgrading, so a vault failure is a
	// plain HTTP error rather than a broken socket. It is handed only to the
	// proxy sidecar, never to the client the user drives.
	spec := dbgw.Spec{Engine: ep.Engine, Version: ep.EngineVersion, Host: ep.Address, Port: ep.port(target.Database)}
	switch {
	case len(g.UserSecret) > 0:
		spec.Username, spec.Password = g.Username, string(g.UserSecret)
	default:
		opened, err := h.Vault.Open(r.Context(), g.CredentialID)
		if err != nil {
			h.Log.Error("open credential", "id", g.CredentialID, "err", err)
			httpx.WriteError(w, http.StatusConflict, "credential_unavailable", "credential could not be opened")
			return
		}
		defer opened.Close()
		spec.Username, spec.Password = opened.Username, opened.Password
	}
	// Default the database name to the login role, the common convention, when
	// the target does not pin one.
	spec.Database = spec.Username

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(1 << 20)

	s := &session.Session{UserID: g.UserID, PolicyID: g.PolicyID, TargetID: ep.TargetID,
		Protocol: g.Protocol, CredentialID: g.CredentialID, ClientIP: ip, UserAgent: r.UserAgent()}
	if err := h.Sessions.Start(r.Context(), s); err != nil {
		h.Log.Error("start session", "err", err)
		_ = ws.Close(websocket.StatusInternalError, "could not start session")
		return
	}
	spec.SessionID = s.ID
	actor := audit.Actor{UserID: g.UserID, IP: ip}
	endWith := func(reason, msg string) {
		_ = h.Sessions.End(context.Background(), s.ID, reason)
		h.record(r, actor.Event("session.end", "access_session", s.ID, audit.Success, map[string]string{"reason": reason, "target_id": ep.LiveKey}))
		if msg != "" {
			_ = ws.Close(websocket.StatusPolicyViolation, msg)
		}
	}

	rec, uri, err := recording.NewAsciicast(r.Context(), h.Storage, s.ID+".cast", recording.Header{Width: cols, Height: rows, Title: ep.Name,
		Env: map[string]string{"ZANSKAR_SESSION": s.ID}})
	if err != nil {
		h.Log.Error("start recording", "err", err)
		endWith(session.EndError, "recording could not be started; session refused")
		return
	}
	recRow := &session.Recording{SessionID: s.ID, Format: "asciicast", StorageURI: uri}
	if err := h.Sessions.CreateRecording(r.Context(), recRow); err != nil {
		h.Log.Error("register recording", "err", err)
		_, _, _ = rec.Close()
		endWith(session.EndError, "recording could not be registered; session refused")
		return
	}
	h.record(r, actor.Event("session.start", "access_session", s.ID, audit.Success,
		map[string]any{"target_id": ep.LiveKey, "protocol": g.Protocol, "policy_id": g.PolicyID, "recording_id": recRow.ID, "engine": ep.Engine}))

	ctx := h.Registry.Add(r.Context(), gateway.Live{SessionID: s.ID, UserID: g.UserID, TargetID: ep.LiveKey, Protocol: g.Protocol})
	defer h.Registry.Remove(s.ID)

	reason, berr := dbgw.Bridge(ctx, h.Log, h.DockerPath, spec, ws, rec, cols, rows, dbgw.Limits{Idle: g.IdleTimeout, Max: g.MaxSession, SessionID: s.ID})
	size, sum, cerr := rec.Close()
	if cerr != nil {
		h.Log.Error("close recording", "session", s.ID, "err", cerr)
	}
	if err := h.Sessions.FinishRecording(context.Background(), recRow.ID, size, sum); err != nil {
		h.Log.Error("finish recording", "session", s.ID, "err", err)
	}
	if berr != nil {
		h.Log.Warn("db bridge ended with error", "session", s.ID, "err", berr)
		if reason == "" || reason == "error" {
			reason = session.EndError
		}
	}
	endWith(reason, "")
	_ = ws.Close(websocket.StatusNormalClosure, reason)
}
