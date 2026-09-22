// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/user"
)

// Principal is the authenticated caller attached to a request context.
type Principal struct {
	Session *Session
	User    *user.User
}

type ctxKey int

const principalKey ctxKey = iota

// FromContext returns the caller, if any.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey).(*Principal)
	return p, ok && p != nil
}

const clientIPKey ctxKey = iota + 1

// WithClientIP returns ctx carrying the resolved client address. RealIP sets it
// once per request so handlers, audit rows and the access log all agree.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey, ip)
}

// ClientIP returns the address the request came from, without a port. Behind a
// trusted reverse proxy this is the forwarded client address resolved by
// RealIP; otherwise it is the peer address. Proxy headers are never believed
// unless RealIP established that the peer is a trusted proxy, because a client
// that could forge this would forge the address lockouts, rate limits and audit
// rows are keyed on.
func ClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey).(string); ok && ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RealIP resolves the client address from X-Forwarded-For when the immediate
// peer is one of the trusted proxies, and stores it for ClientIP.
//
// Anyone can send X-Forwarded-For, so it is only believable when the connection
// itself comes from a proxy we run. The header is then read right to left,
// skipping entries that are themselves trusted proxies: the first untrusted
// entry is the closest hop our own proxy actually observed. A client that
// prepends forged entries cannot move that boundary, because its forgeries sit
// to the left of the address the proxy appended.
//
// With no trusted proxies configured the peer address is used unchanged.
func RealIP(trusted []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ip := resolveClientIP(r, trusted); ip != "" {
				r = r.WithContext(WithClientIP(r.Context(), ip))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func resolveClientIP(r *http.Request, trusted []netip.Prefix) string {
	peer, ok := parseAddr(r.RemoteAddr)
	if !ok {
		return ""
	}
	if len(trusted) == 0 || !trustedAddr(peer, trusted) {
		return peer.String()
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		addr, ok := parseAddr(strings.TrimSpace(hops[i]))
		if !ok || trustedAddr(addr, trusted) {
			continue
		}
		return addr.String()
	}
	return peer.String()
}

// parseAddr accepts "host", "host:port" and IPv4-mapped IPv6, returning a
// comparable address.
func parseAddr(s string) (netip.Addr, bool) {
	if s == "" {
		return netip.Addr{}, false
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap(), true
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		if addr, err := netip.ParseAddr(host); err == nil {
			return addr.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

func trustedAddr(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Middleware resolves sessions and enforces access rules.
type Middleware struct {
	Sessions *Sessions
	Users    *user.Repo
	Log      *slog.Logger
}

// Authenticate attaches a Principal when the cookie names a live session and
// an active user. It never rejects; RequireAuth does that.
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(CookieName)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		sess, err := m.Sessions.Lookup(r.Context(), c.Value)
		if err != nil {
			if !errors.Is(err, ErrNoSession) {
				m.Log.Error("session lookup", "err", err)
			}
			m.Sessions.ClearCookie(w)
			next.ServeHTTP(w, r)
			return
		}
		u, err := m.Users.GetByID(r.Context(), sess.UserID)
		if err != nil || u.IsLocked(time.Now()) {
			m.Sessions.ClearCookie(w)
			next.ServeHTTP(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, &Principal{Session: sess, User: u})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAuth rejects anonymous callers and callers who still owe a second
// factor. Handlers that must run before MFA (the TOTP verify endpoint)
// use RequirePartialAuth instead.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := FromContext(r.Context())
		if !ok {
			WriteError(w, http.StatusUnauthorized, "unauthenticated", "sign in required")
			return
		}
		if !p.Session.MFAVerified {
			WriteError(w, http.StatusUnauthorized, "mfa_required", "second factor required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePartialAuth admits any live session, MFA-verified or not.
func RequirePartialAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := FromContext(r.Context()); !ok {
			WriteError(w, http.StatusUnauthorized, "unauthenticated", "sign in required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireRole admits callers holding any of the roles. It implies RequireAuth.
func RequireRole(roles ...user.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := FromContext(r.Context())
			for _, role := range roles {
				if p.User.HasRole(role) {
					next.ServeHTTP(w, r)
					return
				}
			}
			WriteError(w, http.StatusForbidden, "forbidden", "insufficient role")
		}))
	}
}

// CSRF guards every mutating request. Two independent checks: the Origin (or
// Sec-Fetch-Site) header must be same-origin, and an authenticated call must
// carry the session-bound X-CSRF-Token header. Unauthenticated mutating calls
// (login) get only the origin check.
func (m *Middleware) CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if !sameOrigin(r) {
			WriteError(w, http.StatusForbidden, "csrf_invalid", "cross-origin request rejected")
			return
		}
		if p, ok := FromContext(r.Context()); ok {
			if !m.Sessions.CheckCSRF(p.Session.ID, r.Header.Get("X-CSRF-Token")) {
				WriteError(w, http.StatusForbidden, "csrf_invalid", "missing or invalid X-CSRF-Token")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Non-browser client (curl, SDK). Cookies are SameSite=Strict, so a
		// browser could not have produced this without an Origin header.
		return true
	}
	origin = strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	return strings.EqualFold(origin, r.Host)
}

// APIError is the JSON error body shared by every handler.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// WriteError writes a JSON error.
func WriteError(w http.ResponseWriter, status int, code, msg string) {
	WriteJSON(w, status, APIError{Code: code, Message: msg})
}

// WriteJSON writes v with the right headers.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
