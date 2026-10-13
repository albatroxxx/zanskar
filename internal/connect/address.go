// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"errors"
	"net"
	"net/http"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/ticket"
)

// addressRefusedMsg is what the user is told. The address stays out of it,
// as it stays out of everything a user is shown about a target (myTargets),
// and it is short enough for a WebSocket close frame.
const addressRefusedMsg = "the gateway does not connect to this target's address; an administrator must correct it"

// checkAddress looks the endpoint's address up once and applies the gateway's
// address rules to every answer (target.Prober.Resolve; a nil Prober applies
// them with no exception). It returns the address to dial. An address that
// passed when it was saved and probed can still lead somewhere the gateway
// must never connect to by the time a session dials it: a row saved before
// the rules covered it, or a name that now resolves elsewhere. A refusal is
// audited as a failed connect; a lookup that fails is only logged, like a
// failed dial.
func (h *Handler) checkAddress(r *http.Request, g *ticket.Grant, ep *endpoint) (net.IP, error) {
	ip, err := h.Prober.Resolve(r.Context(), ep.Address)
	switch {
	case errors.Is(err, target.ErrAddressForbidden):
		h.addressRefused(r, g, ep, err)
	case err != nil:
		h.Log.Warn("target address lookup failed", "target", ep.LiveKey, "err", err)
	}
	return ip, err
}

// addressRefused logs and audits a session refused for its target's address.
func (h *Handler) addressRefused(r *http.Request, g *ticket.Grant, ep *endpoint, err error) {
	h.Log.Warn("target address refused", "target", ep.LiveKey, "err", err)
	h.record(r, actorFor(g.UserID, auth.ClientIP(r)).Event(audit.SessionConnect, "target", ep.LiveKey, audit.Failure,
		map[string]any{"protocol": g.Protocol, "reason": "address_forbidden", "error": err.Error()}))
}

// refuseAddress answers a failed checkAddress before the WebSocket upgrade: a
// refused address as the admin API answers one, a failed lookup as a failed
// dial.
func refuseAddress(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, target.ErrAddressForbidden) {
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, "address_forbidden", addressRefusedMsg)
		return
	}
	httpx.WriteError(w, r, http.StatusConflict, "target_unavailable", "could not connect to the target")
}
