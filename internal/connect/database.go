// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"net/http"
	"strconv"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway/dbgw"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/protocol"
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
	// A database target is never probed, so this is the first time its name
	// is looked up. The sidecar is still handed the name, not this address,
	// because verify-full checks the database's certificate against the
	// name; it looks the name up again itself.
	if _, err := h.checkAddress(r, g, ep); err != nil {
		refuseAddress(w, r, err)
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
	if spec.Database == "" && spec.Engine == protocol.Postgres {
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

	run, ok := h.startRun(r, ws, g, ep, ip)
	if !ok {
		return
	}
	spec.SessionID = run.s.ID
	run.startDetails = map[string]any{"engine": ep.Engine}
	rec, recRow, ok := run.asciicast(ep.Name, cols, rows)
	if !ok {
		return
	}
	ctx, done := run.live()
	defer done()

	reason, berr := dbgw.Bridge(ctx, h.Log, h.DockerPath, spec, ws, rec, cols, rows, dbgw.Limits{Idle: g.IdleTimeout, Max: g.MaxSession, SessionID: run.s.ID})
	run.finish(rec, recRow, reason, berr)
}

// liveDatabaseSessions counts the database sessions this gateway is running.
func (h *Handler) liveDatabaseSessions() int {
	n := 0
	for _, l := range h.Registry.List() {
		if l.Protocol == protocol.Database {
			n++
		}
	}
	return n
}
