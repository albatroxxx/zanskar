// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/gateway/browsergw"
	"github.com/albatroxxx/zanskar/internal/gateway/guac"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/ticket"
)

// browser opens an application session (ADR 0034): the upstream's host is
// resolved through the address rules, a browser and its relay are started
// beside the gateway, and guacd draws the browser as a VNC desktop through
// the same bridge, recording and limits as any desktop. The ticket is
// redeemed and the endpoint resolved by the caller.
func (h *Handler) browser(w http.ResponseWriter, r *http.Request, g *ticket.Grant, ep *endpoint, ip, guacdAddr string) {
	browserImage := ""
	if h.BrowserImage != nil {
		browserImage = h.BrowserImage()
	}
	relayImage := ""
	if h.DBProxyImage != nil {
		relayImage = h.DBProxyImage()
	}
	if browserImage == "" || relayImage == "" {
		httpx.WriteError(w, r, http.StatusNotImplemented, "protocol_unavailable", "application sessions are not configured on this gateway: no browser or relay image")
		return
	}
	upstream, err := target.ParseUpstream(ep.AppUpstream)
	if err != nil {
		httpx.WriteError(w, r, http.StatusConflict, "target_unavailable", "target is not an application")
		return
	}
	// The upstream is dialled by the relay, not by the gateway, at the one
	// address the gateway resolved here under the rules every target obeys.
	upstreamIP, err := h.checkAddress(r, g, ep)
	if err != nil {
		refuseAddress(w, r, err)
		return
	}
	if h.AppsMaxSessions > 0 && h.Registry != nil && h.liveSessions(protocol.HTTP) >= h.AppsMaxSessions {
		h.record(r, actorFor(g.UserID, ip).Event(audit.SessionConnect, "target", ep.LiveKey, audit.Failure,
			map[string]any{"protocol": g.Protocol, "reason": "too_many_sessions", "limit": h.AppsMaxSessions}))
		httpx.WriteError(w, r, http.StatusServiceUnavailable, "too_many_sessions", "the gateway is running its maximum number of application sessions; try again in a moment")
		return
	}
	width, height, dpi := screenSize(r)
	if width == 0 || height == 0 {
		width, height = 1280, 800
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"guacamole"}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(4 << 20)

	run, ok := h.startRun(r, ws, g, ep, ip)
	if !ok {
		return
	}
	run.tell = func(msg string) {
		wctx, cancel := detach(r.Context(), frameTimeout)
		_ = ws.Write(wctx, websocket.MessageText, []byte(guac.ErrorInstruction(msg, guac.StatusSessionClosed)))
		cancel()
	}
	// The console's tunnel drops a socket that stays silent for fifteen
	// seconds, and starting the containers takes longer than that on a slow
	// host, or the first time, when the images are pulled. A nop every few
	// seconds keeps the tunnel open until guacd's first instruction; the
	// client ignores it, as it ignores the bridge's heartbeat later.
	beat := h.StartKeepalive
	if beat <= 0 {
		beat = 3 * time.Second
	}
	kaCtx, stopKeepalive := context.WithCancel(r.Context())
	kaDone := make(chan struct{})
	go func() {
		defer close(kaDone)
		t := time.NewTicker(beat)
		defer t.Stop()
		for {
			select {
			case <-kaCtx.Done():
				return
			case <-t.C:
				wctx, cancel := context.WithTimeout(kaCtx, frameTimeout)
				err := ws.Write(wctx, websocket.MessageText, []byte(guac.Encode("nop")))
				cancel()
				if err != nil {
					return
				}
			}
		}
	}()
	bs, err := browsergw.Start(r.Context(), h.Log, h.DockerPath, browsergw.Spec{
		SessionID: run.s.ID, Upstream: upstream, UpstreamIP: upstreamIP, TLSCA: ep.TLSCA,
		Width: width, Height: height, DevTools: run.g.AllowDevTools, BrowserImage: browserImage, RelayImage: relayImage, StateDir: h.StateDir,
	})
	// Nothing else writes to the socket until the keepalive has stopped.
	stopKeepalive()
	<-kaDone
	if err != nil {
		h.Log.Warn("application browser failed to start", "target", ep.LiveKey, "err", err)
		run.end(session.EndError, "the application's browser could not be started on the gateway", nil)
		return
	}
	defer bs.Close()

	// What guacd sees is a VNC server; the session itself keeps its http
	// protocol in its row, the registry and the audit trail.
	params := guac.Params{Protocol: protocol.VNC, Args: map[string]string{
		"hostname":      bs.VNCAddr[:len(bs.VNCAddr)-len(":5900")],
		"port":          "5900",
		"password":      bs.Password,
		"disable-copy":  strconv.FormatBool(!g.AllowClipboard),
		"disable-paste": strconv.FormatBool(!g.AllowClipboard),
	}, Image: []string{"image/png", "image/jpeg", "image/webp"}, Width: width, Height: height, DPI: dpi}
	if tz := r.URL.Query().Get("tz"); tz != "" && len(tz) < 64 {
		params.Timezone = tz
	}
	h.serveGuac(r, ws, run, g, ep, params, guacdAddr)
}

// liveSessions counts the live sessions of one protocol.
func (h *Handler) liveSessions(proto string) int {
	n := 0
	for _, l := range h.Registry.List() {
		if l.Protocol == proto {
			n++
		}
	}
	return n
}
