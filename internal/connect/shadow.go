// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/guac"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

// ShadowHandler lets admins and auditors watch a live session read-only
// (ADR 0006). Terminal sessions are fanned out from the gateway's tap with
// a scrollback replay; desktop sessions join the guacd connection in
// read-only mode. Every watch is audited with the watcher and the owner.
type ShadowHandler struct {
	Registry  *gateway.Registry
	Audit     *audit.Log
	Log       *slog.Logger
	GuacdAddr string
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
		httpx.WriteError(w, http.StatusNotFound, "not_live", "session is not live on this gateway")
		return
	}
	actor := audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}
	details := map[string]string{"session_id": live.SessionID, "target_id": live.TargetID, "owner_user_id": live.UserID, "protocol": live.Protocol}

	switch live.Protocol {
	case "ssh", "winrm":
		h.shadowTerminal(w, r, live, actor, details)
	case "rdp", "vnc":
		h.shadowDesktop(w, r, live, actor, details)
	default:
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "protocol cannot be shadowed")
	}
}

func (h *ShadowHandler) shadowTerminal(w http.ResponseWriter, r *http.Request, live gateway.Live, actor audit.Actor, details map[string]string) {
	tap := live.Tap
	if tap == nil {
		httpx.WriteError(w, http.StatusNotFound, "not_live", "session has no output stream")
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ch, replay, cancel := tap.Subscribe()
	defer cancel()
	h.record(r, actor.Event("session.shadow.start", "access_session", live.SessionID, audit.Success, details))
	defer h.record(r, actor.Event("session.shadow.end", "access_session", live.SessionID, audit.Success, details))

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
				wctx, wcancel := context.WithTimeout(context.Background(), 2*time.Second)
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
	if h.GuacdAddr == "" || live.GuacID == "" {
		httpx.WriteError(w, http.StatusNotFound, "not_live", "desktop session cannot be joined")
		return
	}
	width, _ := strconv.Atoi(r.URL.Query().Get("width"))
	height, _ := strconv.Atoi(r.URL.Query().Get("height"))
	timeout := h.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	gc, err := guac.Join(r.Context(), h.GuacdAddr, live.GuacID, width, height, timeout)
	if err != nil {
		h.Log.Warn("guacd join failed", "session", live.SessionID, "err", err)
		httpx.WriteError(w, http.StatusConflict, "join_failed", "could not join the desktop session")
		return
	}
	defer func() { _ = gc.Close() }()
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"guacamole"}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	h.record(r, actor.Event("session.shadow.start", "access_session", live.SessionID, audit.Success, details))
	defer h.record(r, actor.Event("session.shadow.end", "access_session", live.SessionID, audit.Success, details))
	if err := ws.Write(r.Context(), websocket.MessageText, []byte(guac.Encode("", live.SessionID))); err != nil {
		return
	}
	if err := guac.Relay(r.Context(), gc, ws); err != nil {
		h.Log.Warn("shadow relay ended with error", "session", live.SessionID, "err", err)
	}
	_ = ws.Close(websocket.StatusNormalClosure, "session_ended")
}

func (h *ShadowHandler) record(r *http.Request, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if _, err := h.Audit.Record(context.WithoutCancel(r.Context()), e); err != nil {
		h.Log.Error("audit record failed", "action", e.Action, "err", err)
	}
}
