// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/guac"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/user"
)

// ShadowHandler lets admins and auditors watch a live session read-only
// (ADR 0006). Terminal sessions are fanned out from the gateway's tap with
// a scrollback replay; desktop sessions join the guacd connection in
// read-only mode. Every watch is audited with the watcher and the owner.
type ShadowHandler struct {
	Registry *gateway.Registry
	Audit    *audit.Log
	Log      *slog.Logger
	// GuacdAddr returns the guacd address; a function so the runtime
	// setting applies live. Nil or empty means desktops are off.
	GuacdAddr func() string
	// DialTimeout bounds the guacd join.
	DialTimeout time.Duration
}

// Register mounts GET /ws/shadow/{sessionID}. The cookie session
// authenticates the upgrade; websocket.Accept enforces same-origin.
func (h *ShadowHandler) Register(mux *http.ServeMux) {
	mux.Handle("GET /ws/shadow/{sessionID}", auth.RequireRole(user.RoleAdmin, user.RoleAuditor)(http.HandlerFunc(h.shadow)))
}

type shadowControl struct {
	T      string `json:"t"`
	Replay bool   `json:"replay,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func (h *ShadowHandler) shadow(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id := r.PathValue("sessionID")
	live, ok := h.Registry.Get(id)
	if !ok {
		httpx.WriteError(w, r, http.StatusNotFound, "not_live", "session is not live on this gateway")
		return
	}
	actor := audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}
	details := map[string]string{"session_id": live.SessionID, "target_id": live.TargetID, "owner_user_id": live.UserID, "protocol": live.Protocol}

	switch {
	case protocol.Terminal(live.Protocol):
		h.shadowTerminal(w, r, live, actor, details)
	case protocol.Desktop(live.Protocol), live.Protocol == protocol.HTTP:
		// An application session (ADR 0034) is drawn through guacd too.
		h.shadowDesktop(w, r, live, actor, details)
	default:
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", "protocol cannot be shadowed")
	}
}

func (h *ShadowHandler) shadowTerminal(w http.ResponseWriter, r *http.Request, live gateway.Live, actor audit.Actor, details map[string]string) {
	tap := live.Tap
	if tap == nil {
		httpx.WriteError(w, r, http.StatusNotFound, "not_live", "session has no output stream")
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ch, replay, cancel := tap.Subscribe()
	defer cancel()
	// Counted as watching from here, while the stream reaches this socket;
	// the first watcher other than the owner releases a session held for a
	// second person (ADR 0042).
	h.Registry.Watch(live.SessionID, actor.UserID, +1)
	defer h.Registry.Watch(live.SessionID, actor.UserID, -1)
	h.record(r, actor.Event(audit.SessionShadowStart, "access_session", live.SessionID, audit.Success, details))
	defer h.record(r, actor.Event(audit.SessionShadowEnd, "access_session", live.SessionID, audit.Success, details))

	ctx, stop := context.WithCancel(r.Context())
	defer stop()
	send := func(v any) error {
		b, _ := json.Marshal(v)
		return ws.Write(ctx, websocket.MessageText, b)
	}
	if err := send(shadowControl{T: "ready", Replay: len(replay) > 0}); err != nil {
		return
	}
	if len(replay) > 0 {
		if err := ws.Write(ctx, websocket.MessageBinary, replay); err != nil {
			return
		}
	}
	// Drain and ignore anything the watcher sends; the socket is read-only.
	go func() {
		defer stop()
		for {
			if _, _, err := ws.Read(ctx); err != nil {
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case chunk, ok := <-ch:
			if !ok {
				wctx, wcancel := detach(ctx, frameTimeout)
				b, _ := json.Marshal(shadowControl{T: "end", Reason: "session_ended"})
				_ = ws.Write(wctx, websocket.MessageText, b)
				wcancel()
				_ = ws.Close(websocket.StatusNormalClosure, "session_ended")
				return
			}
			if err := ws.Write(ctx, websocket.MessageBinary, chunk); err != nil {
				return
			}
		}
	}
}

func (h *ShadowHandler) shadowDesktop(w http.ResponseWriter, r *http.Request, live gateway.Live, actor audit.Actor, details map[string]string) {
	guacdAddr := ""
	if h.GuacdAddr != nil {
		guacdAddr = h.GuacdAddr()
	}
	if guacdAddr == "" {
		httpx.WriteError(w, r, http.StatusNotFound, "not_live", "desktop session cannot be joined")
		return
	}
	if live.GuacID == "" {
		// Held for a watcher, or a moment from guacd (ADR 0042 amendment).
		h.shadowHeldDesktop(w, r, live, actor, details, guacdAddr)
		return
	}
	width, height, _ := screenSize(r)
	timeout := h.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	gc, err := guac.Join(r.Context(), guacdAddr, live.GuacID, width, height, timeout)
	if err != nil {
		h.Log.Warn("guacd join failed", "session", live.SessionID, "err", err)
		httpx.WriteError(w, r, http.StatusConflict, "join_failed", "could not join the desktop session")
		return
	}
	defer func() { _ = gc.Close() }()
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"guacamole"}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	// Counted as watching, as a terminal's watcher is (ADR 0042).
	h.Registry.Watch(live.SessionID, actor.UserID, +1)
	defer h.Registry.Watch(live.SessionID, actor.UserID, -1)
	h.record(r, actor.Event(audit.SessionShadowStart, "access_session", live.SessionID, audit.Success, details))
	defer h.record(r, actor.Event(audit.SessionShadowEnd, "access_session", live.SessionID, audit.Success, details))
	if err := ws.Write(r.Context(), websocket.MessageText, []byte(guac.Encode("", live.SessionID))); err != nil {
		return
	}
	if err := guac.Relay(r.Context(), gc, ws); err != nil {
		h.Log.Warn("shadow relay ended with error", "session", live.SessionID, "err", err)
	}
	_ = ws.Close(websocket.StatusNormalClosure, "session_ended")
}

// heldPoll is how often a watcher of a held desktop looks for guacd's
// connection; heldBeat how often it keeps the console's tunnel open.
var (
	heldPoll = 200 * time.Millisecond
	heldBeat = 3 * time.Second
)

// shadowHeldDesktop watches a desktop that guacd is not drawing yet: one held
// for a second person (ADR 0042 amendment), or in the moment before guacd
// answers. The watcher is counted at once, which releases a held session;
// the view joins guacd as soon as the session has dialled it, so the
// watcher sees it from its first frame. The session ending first, or
// nothing drawn within watchWait, closes the view with the reason.
func (h *ShadowHandler) shadowHeldDesktop(w http.ResponseWriter, r *http.Request, live gateway.Live, actor audit.Actor, details map[string]string, guacdAddr string) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"guacamole"}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	h.Registry.Watch(live.SessionID, actor.UserID, +1)
	defer h.Registry.Watch(live.SessionID, actor.UserID, -1)
	h.record(r, actor.Event(audit.SessionShadowStart, "access_session", live.SessionID, audit.Success, details))
	defer h.record(r, actor.Event(audit.SessionShadowEnd, "access_session", live.SessionID, audit.Success, details))
	ctx := r.Context()
	write := func(raw string) error { return ws.Write(ctx, websocket.MessageText, []byte(raw)) }
	if write(guac.Encode("", live.SessionID)) != nil || write(guac.Encode("zanskar", "waiting", "the session starts now that you watch it")) != nil {
		return
	}
	closeWith := func(msg string) {
		_ = write(guac.ErrorInstruction(msg, guac.StatusSessionClosed))
		_ = ws.Close(websocket.StatusNormalClosure, "session_ended")
	}
	poll := time.NewTicker(heldPoll)
	defer poll.Stop()
	beat := time.NewTicker(heldBeat)
	defer beat.Stop()
	give := time.NewTimer(watchWait)
	defer give.Stop()
	var guacID string
	for guacID == "" {
		select {
		case <-ctx.Done():
			return
		case <-give.C:
			closeWith("the session did not start")
			return
		case <-beat.C:
			if write(guac.Encode("nop")) != nil {
				return
			}
		case <-poll.C:
			l, ok := h.Registry.Get(live.SessionID)
			if !ok {
				closeWith("the session ended before it started")
				return
			}
			guacID = l.GuacID
		}
	}
	width, height, _ := screenSize(r)
	timeout := h.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	gc, err := guac.Join(ctx, guacdAddr, guacID, width, height, timeout)
	if err != nil {
		h.Log.Warn("guacd join failed", "session", live.SessionID, "err", err)
		closeWith("could not join the desktop session")
		return
	}
	defer func() { _ = gc.Close() }()
	if err := guac.Relay(ctx, gc, ws); err != nil {
		h.Log.Warn("shadow relay ended with error", "session", live.SessionID, "err", err)
	}
	_ = ws.Close(websocket.StatusNormalClosure, "session_ended")
}

func (h *ShadowHandler) record(r *http.Request, e audit.Event) {
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, e)
}
