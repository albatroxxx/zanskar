// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
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
	extras, unreachable, err := h.appEndpoints(r.Context(), ep)
	if err != nil {
		h.addressRefused(r, g, ep, err)
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
	// The audit says whether this session's relay let dependencies out
	// (2026-11-03), and which origins were left out of it.
	run.startDetails = map[string]any{"dependencies": ep.AppDependencies}
	if len(unreachable) > 0 {
		run.startDetails["unreachable_origins"] = unreachable
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
		SessionID: run.s.ID, Name: ep.Name, Upstream: upstream, UpstreamIP: upstreamIP, Endpoints: extras, TLSCA: ep.TLSCA,
		PublicDependencies: ep.AppDependencies == target.DependenciesPublic,
		Width:              width, Height: height, DevTools: run.g.AllowDevTools, BrowserImage: browserImage, RelayImage: relayImage, StateDir: h.StateDir,
		Debug: h.Log.Enabled(r.Context(), slog.LevelDebug),
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

// appEndpoints resolves an application's further origins (ADR 0037,
// amended 2026-11-02) under the address rules every target obeys, each host
// once and all at once, and pins the answers: the relay dials those
// addresses and nothing else. A forbidden answer for any of them refuses the
// session, as the upstream's would, since it means the application names a
// place the gateway must never connect to. A name that does not resolve
// leaves its origin out of this session, reported in unreachable, so one
// endpoint that is down does not keep the rest of the application from
// opening.
func (h *Handler) appEndpoints(ctx context.Context, ep *endpoint) (out []browsergw.Endpoint, unreachable []string, err error) {
	if len(ep.AppEndpoints) == 0 {
		return nil, nil, nil
	}
	type answer struct {
		ip  net.IP
		err error
	}
	urls := make([]*url.URL, len(ep.AppEndpoints))
	hosts := map[string]*answer{}
	for i, e := range ep.AppEndpoints {
		if u, perr := target.ParseUpstream(e.URL); perr == nil {
			urls[i] = u
			hosts[u.Hostname()] = &answer{}
		}
	}
	var wg sync.WaitGroup
	for host, a := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.ip, a.err = h.Prober.Resolve(ctx, host)
		}()
	}
	wg.Wait()
	for i, e := range ep.AppEndpoints {
		u := urls[i]
		if u == nil {
			unreachable = append(unreachable, e.URL)
			continue
		}
		switch a := hosts[u.Hostname()]; {
		case errors.Is(a.err, target.ErrAddressForbidden):
			return nil, nil, a.err
		case a.err != nil:
			h.Log.Warn("application endpoint lookup failed", "target", ep.LiveKey, "endpoint", u.String(), "err", a.err)
			unreachable = append(unreachable, u.String())
		default:
			out = append(out, browsergw.Endpoint{Name: e.Name, URL: u, IP: a.ip})
		}
	}
	return out, unreachable, nil
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
