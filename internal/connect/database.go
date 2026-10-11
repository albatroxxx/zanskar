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
	g, ok := h.redeem(w, r)
	if !ok {
		return
	}
	defer zero(g.UserSecret)
	if target.Protocol(g.Protocol) != target.Database {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", "ticket is not for database")
		return
	}
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))

	ep, err := h.resolveGrant(r.Context(), g)
	if err != nil || !ep.Active || ep.Engine == "" {
		httpx.WriteError(w, r, http.StatusConflict, "target_unavailable", "target is no longer available")
		return
	}

	// Resolve the upstream credential before upgrading, so a vault failure is a
	// plain HTTP error rather than a broken socket. It is handed only to the
	// proxy sidecar, never to the client the user drives.
	spec := dbgw.Spec{Engine: ep.Engine, Version: ep.EngineVersion, Host: ep.Address, Port: ep.port(target.Database),
		TLSMode: ep.TLSMode, TLSCA: ep.TLSCA}
	switch {
	case len(g.UserSecret) > 0:
		spec.Username, spec.Password = g.Username, string(g.UserSecret)
	default:
		opened, err := h.Vault.Open(r.Context(), g.CredentialID)
		if err != nil {
			h.Log.Error("open credential", "id", g.CredentialID, "err", err)
			httpx.WriteError(w, r, http.StatusConflict, "credential_unavailable", "credential could not be opened")
			return
		}
		defer opened.Close()
		spec.Username, spec.Password = opened.Username, opened.Password
	}
	// The target names the database to open; without one, PostgreSQL gets
	// the convention of a database named after the role, while MySQL and
	// MariaDB open with no schema selected and the user picks one with USE.
	spec.Database = ep.DatabaseName
	if spec.Database == "" && spec.Engine == "postgres" {
		spec.Database = spec.Username
	}
	if h.DBProxyImage != nil {
		spec.ProxyImage = h.DBProxyImage()
	}

	// The cap on concurrent database sessions (ADR 0017), each two containers
	// and a network on this host. It is counted, not reserved, so a burst of
	// simultaneous starts can overshoot by the burst. Refused here, before the
	// upgrade, because no status can follow it.
	if h.DBMaxSessions > 0 && h.Registry != nil && h.liveDatabaseSessions() >= h.DBMaxSessions {
		h.record(r, actorFor(g.UserID, ip).Event(audit.SessionConnect, "target", ep.LiveKey, audit.Failure,
			map[string]any{"protocol": g.Protocol, "reason": "too_many_sessions", "limit": h.DBMaxSessions}))
		httpx.WriteError(w, r, http.StatusServiceUnavailable, "too_many_sessions", "the gateway is running its maximum number of database sessions; try again in a moment")
		return
	}

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
		h.record(r, actor.Event(audit.SessionEnd, "access_session", s.ID, audit.Success, map[string]string{"reason": reason, "target_id": ep.LiveKey}))
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
	recRow := &session.Recording{SessionID: s.ID, Format: "asciicast", StorageURI: uri, RetentionUntil: retentionUntil(g)}
	if err := h.Sessions.CreateRecording(r.Context(), recRow); err != nil {
		h.Log.Error("register recording", "err", err)
		_, _, _ = rec.Close()
		endWith(session.EndError, "recording could not be registered; session refused")
		return
	}
	h.record(r, actor.Event(audit.SessionStart, "access_session", s.ID, audit.Success,
		map[string]any{"target_id": ep.LiveKey, "protocol": g.Protocol, "policy_id": g.PolicyID, "recording_id": recRow.ID, "engine": ep.Engine}))

	ctx := h.Registry.Add(r.Context(), gateway.Live{SessionID: s.ID, UserID: g.UserID, TargetID: ep.LiveKey, Protocol: g.Protocol, PolicyID: g.PolicyID})
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

// liveDatabaseSessions counts the database sessions this gateway is running.
func (h *Handler) liveDatabaseSessions() int {
	n := 0
	for _, l := range h.Registry.List() {
		if l.Protocol == string(target.Database) {
			n++
		}
	}
	return n
}
