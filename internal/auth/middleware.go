// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
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

// ClientIP returns the peer address. Proxy headers are ignored until a
// trusted-proxy list exists; trusting them blindly would let a client forge
// the address that lockouts, rate limits and audit rows are keyed on.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
			if err != ErrNoSession {
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
