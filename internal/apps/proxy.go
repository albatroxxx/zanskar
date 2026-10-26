// SPDX-License-Identifier: Apache-2.0

package apps

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/target"
)

// identityHeaders are what an upstream might read a signed-in user from. A
// browser does not send them; one that does is trying to be someone, so they
// are dropped before the upstream sees the request. Authorization stays: it
// belongs to the application.
var identityHeaders = []string{
	"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Preferred-Username", "X-Forwarded-Groups", "X-Forwarded-Access-Token",
	"X-Remote-User", "Remote-User", "X-Auth-Request-User", "X-Auth-Request-Email", "X-Auth-Request-Groups",
	"X-Auth-User", "X-User", "X-Userinfo", "X-Zanskar-User",
}

// ownCookie reports whether a cookie name is the gateway's: the console's,
// an application's, or a state cookie, with or without the __Host- prefix.
func ownCookie(name string) bool {
	return strings.HasPrefix(name, "zanskar_") || strings.HasPrefix(name, "__Host-zanskar_")
}

// originKey carries the application's public origin to ModifyResponse.
type originKey struct{}

// upstream is one application's way out: the parsed origin, a transport that
// pools its connections and verifies its TLS, and the proxy itself.
type upstream struct {
	url       *url.URL
	ca        string
	transport *http.Transport
	proxy     *httputil.ReverseProxy
}

// upstreamFor returns the application's upstream, built once and rebuilt when
// its address or CA bundle changes.
func (h *Handler) upstreamFor(a *Application, targetID string) (*upstream, error) {
	if v, ok := h.upstreams.Load(targetID); ok {
		u := v.(*upstream)
		if u.url.String() == a.Upstream && u.ca == a.TLSCA {
			return u, nil
		}
		h.upstreams.Delete(targetID)
		u.transport.CloseIdleConnections()
	}
	u, err := h.newUpstream(a)
	if err != nil {
		return nil, err
	}
	actual, _ := h.upstreams.LoadOrStore(targetID, u)
	return actual.(*upstream), nil
}

func (h *Handler) newUpstream(a *Application) (*upstream, error) {
	dest, err := target.ParseUpstream(a.Upstream)
	if err != nil {
		return nil, err
	}
	// Verified always: the system roots, or the bundle the administrator
	// gave, and never a way to switch verification off (ADR 0033).
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if a.TLSCA != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(a.TLSCA)) {
			return nil, errors.New("apps: the application's CA bundle holds no certificate")
		}
		tlsCfg.RootCAs = pool
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		// Every connection dials the address the rules checked, never the
		// name: a name that now resolves somewhere forbidden is refused here,
		// and a second lookup could answer differently. TLS still verifies
		// the name, which the transport takes from the URL.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip, err := h.Prober.Resolve(ctx, host)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		},
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	scheme := "https"
	if pu, err := url.Parse(h.PublicURL); err == nil && pu.Scheme != "" {
		scheme = pu.Scheme
	}
	up := &upstream{url: dest, ca: a.TLSCA, transport: tr}
	up.proxy = &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			// The upstream sees its own host name; the address people typed
			// travels in X-Forwarded-Host for applications that build links
			// from it.
			pr.SetURL(dest)
			// Every address header an upstream might trust from its proxy
			// carries the gateway's own answer: the inbound ones were a
			// browser's to write. Rewrite mode already drops the inbound
			// X-Forwarded-* trio; X-Real-IP and Forwarded it leaves alone.
			ip := auth.ClientIP(pr.In)
			pr.Out.Header.Set("X-Forwarded-For", ip)
			pr.Out.Header.Set("X-Real-IP", ip)
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			pr.Out.Header.Set("X-Forwarded-Proto", scheme)
			for _, name := range identityHeaders {
				pr.Out.Header.Del(name)
			}
			stripCookies(pr.Out.Header)
		},
		ModifyResponse: func(resp *http.Response) error {
			origin, _ := resp.Request.Context().Value(originKey{}).(string)
			rewriteLocation(resp.Header, dest, origin)
			sanitizeSetCookies(resp.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.log().Warn("application upstream failed", "request_id", httpx.RequestID(r.Context()), "upstream", dest.Host, "err", err)
			if errors.Is(err, target.ErrAddressForbidden) {
				h.page(w, http.StatusBadGateway, "Application unavailable", "The gateway does not connect to this application's address; an administrator must correct it.", true)
				return
			}
			h.page(w, http.StatusBadGateway, "Application unavailable", "The application did not answer. Try again in a moment.", true)
		},
		ErrorLog: slog.NewLogLogger(h.log().Handler(), slog.LevelWarn),
	}
	return up, nil
}

// stripCookies rebuilds the Cookie header without the gateway's own cookies,
// so an upstream never sees a Zanskar cookie, whatever a browser sends.
func stripCookies(header http.Header) {
	if header.Get("Cookie") == "" {
		return
	}
	var kept []string
	for _, c := range (&http.Request{Header: header}).Cookies() {
		if !ownCookie(c.Name) {
			kept = append(kept, c.Name+"="+c.Value)
		}
	}
	header.Del("Cookie")
	if len(kept) > 0 {
		header.Set("Cookie", strings.Join(kept, "; "))
	}
}

// rewriteLocation points a redirect to the upstream's own origin at the
// application's public one instead; a relative or third-party Location is
// left as it is.
func rewriteLocation(header http.Header, dest *url.URL, origin string) {
	loc := header.Get("Location")
	if loc == "" || origin == "" {
		return
	}
	u, err := url.Parse(loc)
	if err != nil || u.Host == "" || !sameOrigin(u, dest) {
		return
	}
	o, err := url.Parse(origin)
	if err != nil {
		return
	}
	u.Scheme, u.Host = o.Scheme, o.Host
	header.Set("Location", u.String())
}

// sameOrigin compares scheme, host and effective port.
func sameOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

// sanitizeSetCookies keeps an upstream's cookies on the application's own
// host: one that names the gateway's cookies is dropped, and a Domain
// attribute, which would send the cookie to sibling applications or the
// console, is removed. Anything unparsable passes untouched.
func sanitizeSetCookies(header http.Header) {
	lines := header.Values("Set-Cookie")
	if len(lines) == 0 {
		return
	}
	var kept []string
	for _, line := range lines {
		c, err := http.ParseSetCookie(line)
		switch {
		case err != nil:
			kept = append(kept, line)
		case ownCookie(c.Name):
		case c.Domain != "":
			c.Domain = ""
			kept = append(kept, c.String())
		default:
			kept = append(kept, line)
		}
	}
	header.Del("Set-Cookie")
	for _, line := range kept {
		header.Add("Set-Cookie", line)
	}
}

// proxy forwards one request of a live application session and logs it:
// method, path, status, size and time, never the query string or a body
// (ADR 0033), to the gateway's log rather than the audit chain.
func (h *Handler) proxy(w http.ResponseWriter, r *http.Request, label string) {
	ctx := r.Context()
	now := time.Now()
	row := h.session(w, r, label, now)
	if row == nil {
		return
	}
	up, err := h.upstreamFor(&row.Target, row.TargetID)
	if err != nil {
		h.log().Error("application upstream", "app", logSafe(label), "err", err)
		h.page(w, http.StatusBadGateway, "Application unavailable", "This application's upstream is not usable; an administrator must correct it.", true)
		return
	}
	h.touch(ctx, row, now)
	rec := httpx.NewStatusRecorder(w)
	up.proxy.ServeHTTP(rec, r.WithContext(context.WithValue(ctx, originKey{}, h.origin(label))))
	h.log().Info("app",
		"request_id", httpx.RequestID(ctx),
		"app", logSafe(label),
		"user_id", row.UserID,
		"session", row.SessionID,
		"method", r.Method,
		"path", logSafe(r.URL.Path),
		"status", rec.Status,
		"bytes", rec.Bytes,
		"duration_ms", time.Since(now).Milliseconds(),
		"remote", auth.ClientIP(r),
	)
}

// session resolves the request's cookie to a live application session, or
// answers the request and returns nil: a page is sent to the console to sign
// in, a fetch is told the session ended.
func (h *Handler) session(w http.ResponseWriter, r *http.Request, label string, now time.Time) *Row {
	ctx := r.Context()
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		row, err := h.Repo.Lookup(ctx, hashToken(c.Value))
		switch {
		case err == nil && row.EndedAt != nil:
			// Ended elsewhere (an administrator, or another gateway on the
			// same database): the cookie is spent.
			if err := h.Repo.Delete(ctx, row.TokenHash); err != nil {
				h.log().Error("forget application cookie", "err", err)
			}
		case err == nil:
			if reason := h.verdict(row, label, now); reason != "" {
				h.end(row, reason)
			} else {
				return row
			}
		case !errors.Is(err, ErrNotFound):
			h.log().Error("application session lookup", "err", err)
			h.page(w, http.StatusServiceUnavailable, "Try again", "The gateway could not check your session; try again in a moment.", true)
			return nil
		}
	}
	clearCookie(w, cookieName)
	w.Header().Set("Cache-Control", "no-store")
	if !navigation(r) {
		http.Error(w, "your Zanskar session for this application has ended; reload the page to sign in again", http.StatusUnauthorized)
		return nil
	}
	// Applications no longer configured (the public URL removed since the
	// application was enrolled, say) get the reason, not a redirect to
	// nowhere that would loop back here.
	if err := h.Ready(); err != nil {
		h.page(w, http.StatusServiceUnavailable, "Applications unavailable", "Applications are not configured on this gateway: "+err.Error(), false)
		return nil
	}
	// A name nothing is served under is told so here, not sent to the
	// console to find out.
	if t, err := h.Targets.GetByLabel(ctx, label); err != nil || !t.IsApplication() || t.Status != target.StatusActive {
		if err != nil && !errors.Is(err, target.ErrNotFound) {
			h.log().Error("application lookup", "app", logSafe(label), "err", err)
		}
		h.page(w, http.StatusNotFound, "No such application", "Nothing is served at this address.", true)
		return nil
	}
	state, err := randomToken()
	if err != nil {
		h.page(w, http.StatusInternalServerError, "Try again", "The gateway could not start a sign-in; try again in a moment.", true)
		return nil
	}
	setCookie(w, stateCookieName, state, stateTTL)
	q := url.Values{"app": {label}, "state": {state}, "next": {safePath(r.URL.RequestURI())}}
	http.Redirect(w, r, h.PublicURL+LaunchPath+"?"+q.Encode(), http.StatusFound)
	return nil
}
