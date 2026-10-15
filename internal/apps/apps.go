// SPDX-License-Identifier: Apache-2.0

// Package apps serves web applications through the gateway's own reverse
// proxy (ADR 0033). An application is a target with an upstream, served at
// https://<label>.<apps domain>: a host of its own, so no application can
// read the console's cookie or another application's. A browser that
// arrives without a session is sent to the console, which decides access as
// it does for a host (access.Gate) and sends it back with a one-time code;
// the proxy exchanges the code for a cookie valid for that one host, opens an
// access session like any other, and checks it on every request against the
// sign-in it came from, the session's end and the admitting policy's limits.
package apps

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/access"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
)

// Paths the proxy answers itself on every application host. An upstream path
// under /_zanskar/ is not reachable through the gateway.
const (
	enterPath   = "/_zanskar/enter"
	signoutPath = "/_zanskar/signout"
	reserved    = "/_zanskar/"
)

// LaunchPath is the console page a browser is sent to for a session: the
// single-page app there asks the API for a code and sends the browser back.
const LaunchPath = "/launch"

// Cookie names. With TLS they carry the __Host- prefix, which a browser
// accepts only from the host itself, Secure, with no Domain: a sibling
// application cannot plant one.
const (
	cookieBase = "zanskar_app"
	stateBase  = "zanskar_app_state"
	stateTTL   = 5 * time.Minute
	// cookieTTL bounds the cookie in the browser; the session itself ends by
	// the server's rules long before a cookie this old could matter.
	cookieTTL = 12 * time.Hour
)

// Handler is the applications proxy and the console route that hands a
// browser off to it.
type Handler struct {
	Targets  *target.Repo
	Gate     *access.Gate
	Sessions *session.Repo
	Auth     *auth.Sessions
	Repo     *Repo
	Registry *gateway.Registry
	Audit    *audit.Log
	Log      *slog.Logger
	// Prober holds the address rules every connection to an upstream passes,
	// when a session opens and at every dial; nil applies them with no
	// exception.
	Prober *target.Prober
	// Domain returns the apps domain setting; empty means applications are
	// not served.
	Domain func() string
	// PublicURL is the console's origin (ZANSKAR_PUBLIC_URL): where a browser
	// is sent to sign in, and whose scheme and port applications share.
	PublicURL string
	// Secure says the cookies carry Secure and the __Host- prefix: true
	// whenever browsers reach the gateway over TLS.
	Secure bool
	// TLSReady reports why the apps domain cannot be served over TLS yet (no
	// certificate for it), or nil; nil skips the check, as in proxy mode.
	TLSReady func(domain string) error
	// Draining reports a restart in progress: no new session starts.
	Draining func() bool

	once      sync.Once
	codes     *codeStore
	upstreams sync.Map // target id → *upstream
	live      sync.Map // session id → *tracked
}

// Register mounts the console-side route; the application hosts are served
// through ServeHTTP, which the server dispatches to by host.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/me/applications/launch", auth.RequireConnect(http.HandlerFunc(h.launch)))
}

func (h *Handler) store() *codeStore {
	h.once.Do(func() { h.codes = newCodeStore() })
	return h.codes
}

func (h *Handler) domain() string {
	if h.Domain == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(h.Domain()))
}

// Ready reports why applications cannot be served yet, or nil: the apps
// domain, the console's public address and, where the gateway terminates
// TLS, a certificate for the domain. Enrolling an application is refused
// until it is nil (target.AdminHandler.AppsReady).
func (h *Handler) Ready() error {
	domain := h.domain()
	if domain == "" {
		return errors.New("set the apps domain in Settings first: the domain applications are served under, such as apps.example.com, with wildcard DNS for it pointing at the gateway")
	}
	if h.PublicURL == "" {
		return errors.New("applications need ZANSKAR_PUBLIC_URL, the address people reach the console at, so a browser can be sent back to sign in")
	}
	if h.TLSReady != nil {
		if err := h.TLSReady(domain); err != nil {
			return err
		}
	}
	return nil
}

// URL is where a browser opens the application served under label; empty
// when applications cannot be served. The request is not needed today: the
// address comes from ZANSKAR_PUBLIC_URL.
func (h *Handler) URL(_ *http.Request, label string) string {
	if h.Ready() != nil || !target.ValidLabel(label) {
		return ""
	}
	return h.origin(label) + "/"
}

// origin is the application's own origin: the console's scheme and port, the
// label under the apps domain.
func (h *Handler) origin(label string) string {
	u, err := url.Parse(h.PublicURL)
	if err != nil {
		return ""
	}
	host := label + "." + h.domain()
	if port := u.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	}
	return u.Scheme + "://" + host
}

// Serves reports whether host, a request's Host header, names an application.
func (h *Handler) Serves(host string) bool {
	_, ok := h.label(host)
	return ok
}

// label reads the application's label out of a request's host: exactly one
// label under the apps domain.
func (h *Handler) label(host string) (string, bool) {
	domain := h.domain()
	if domain == "" {
		return "", false
	}
	host = strings.ToLower(host)
	if hp, _, err := net.SplitHostPort(host); err == nil {
		host = hp
	}
	label, ok := strings.CutSuffix(host, "."+domain)
	if !ok || !target.ValidLabel(label) {
		return "", false
	}
	return label, true
}

// ServeHTTP answers a request to an application host: the hand-off, the
// sign-out, or the application itself through the proxy.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	label, ok := h.label(r.Host)
	if !ok {
		h.page(w, http.StatusNotFound, "No such application", "Nothing is served at this address.", false)
		return
	}
	switch {
	case r.URL.Path == enterPath:
		h.enter(w, r, label)
	case r.URL.Path == signoutPath:
		h.signout(w, r, label)
	case strings.HasPrefix(r.URL.Path, reserved):
		h.page(w, http.StatusNotFound, "Not found", "This path is the gateway's own and is not forwarded to the application.", true)
	default:
		h.proxy(w, r, label)
	}
}

func (h *Handler) draining() bool { return h.Draining != nil && h.Draining() }

func (h *Handler) cookieName() string {
	if h.Secure {
		return "__Host-" + cookieBase
	}
	return cookieBase
}

func (h *Handler) stateCookieName() string {
	if h.Secure {
		return "__Host-" + stateBase
	}
	return stateBase
}

// setCookie writes a host-only cookie: no Domain, so it never travels to a
// sibling application or the console, and Lax, so the browser sends it on
// the navigation that brings a person back from the console.
func (h *Handler) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure follows whether the gateway serves TLS; false only on plain-HTTP development
		Name: name, Value: value, Path: "/", HttpOnly: true, Secure: h.Secure, SameSite: http.SameSiteLaxMode, MaxAge: int(maxAge / time.Second),
	})
}

func (h *Handler) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- as setCookie
		Name: name, Value: "", Path: "/", HttpOnly: true, Secure: h.Secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// randomToken is 32 random bytes, URL-safe.
func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// hashToken is what the database holds of a cookie, as for sign-ins.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// safePath admits a return path on the application's own host and nothing
// else: it must start with one slash, so it cannot name another host, and
// carry nothing a header could be broken with.
func safePath(p string) string {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") || len(p) > 2048 || strings.ContainsAny(p, "\r\n\x00") {
		return "/"
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	return p
}

// navigation reports whether the browser is loading a page, as against a
// script fetching data: a page is sent to sign in, a fetch is told no.
func navigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	mode := r.Header.Get("Sec-Fetch-Mode")
	return mode == "" || mode == "navigate"
}

func (h *Handler) record(r *http.Request, e audit.Event) {
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, e)
}
