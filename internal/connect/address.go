// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway/guac"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/session"
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
// dial. drawn is a session guacd draws (a desktop, an application).
func refuseAddress(w http.ResponseWriter, r *http.Request, drawn bool, err error) {
	if errors.Is(err, target.ErrAddressForbidden) {
		refuseOpen(w, r, drawn, session.EndError, http.StatusUnprocessableEntity, "address_forbidden", addressRefusedMsg)
		return
	}
	refuseOpen(w, r, drawn, session.EndError, http.StatusConflict, "target_unavailable", "could not connect to the target")
}

// refuseOpen refuses a session before it starts, in words the console
// shows. An HTTP error written before the WebSocket upgrade reaches a
// browser as a failed handshake with nothing in it, so the console could
// only say the session ended because of an error (testing board #183). A
// browser's socket is accepted and closed at once instead, with the words
// where its page reads them: an end frame for a terminal, a guacamole
// error instruction for a drawn session. A request that is not a
// WebSocket upgrade gets the HTTP error.
func refuseOpen(w http.ResponseWriter, r *http.Request, drawn bool, reason string, status int, code, msg string) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		httpx.WriteError(w, r, status, code, msg)
		return
	}
	opts := &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled}
	if drawn {
		opts.Subprotocols = []string{"guacamole"}
	}
	ws, err := websocket.Accept(w, r, opts)
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ctx, cancel := detach(r.Context(), frameTimeout)
	defer cancel()
	frame := guac.ErrorInstruction(msg, guac.StatusSessionClosed)
	if !drawn {
		b, _ := json.Marshal(map[string]string{"t": "end", "reason": reason, "msg": msg})
		frame = string(b)
	}
	_ = ws.Write(ctx, websocket.MessageText, []byte(frame))
	_ = ws.Close(websocket.StatusPolicyViolation, closeReason(msg))
}

// closeReason fits msg in a WebSocket close frame, which carries at most
// 123 bytes (a longer one closes as an internal error with no words), cut
// at a character. The whole of it went in the frame before.
func closeReason(msg string) string {
	const max = 123
	if len(msg) <= max {
		return msg
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut]
}
