// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

// API tokens (ADR 0044) are an administrator's credential for automation:
// the Terraform provider, a pipeline importing the configuration file. A
// request carrying "Authorization: Bearer zapi_..." is that administrator,
// on the configuration API only, with no second factor to prove and no CSRF
// token to carry (a browser cannot attach the header across origins). Any
// other bearer token (SCIM's zscim_) is left to the route that reads it.

// TokenPrefix starts every API token, so a leaked one is recognisable to a
// secret scanner and to the middleware.
const TokenPrefix = "zapi_"

// ErrBadToken is a token that is unknown, expired or revoked.
var ErrBadToken = errors.New("auth: invalid api token")

// TokenStore checks an API token: the user it acts as and its id, or
// ErrBadToken. ip is the caller's address, kept as the token's last use.
type TokenStore interface {
	Authenticate(ctx context.Context, secret, ip string) (userID, tokenID string, err error)
}

// tokenRoute is a part of the API a token may call: a path, or a path
// prefix ending in "/", and the methods allowed on it.
type tokenRoute struct {
	path    string
	methods []string
}

var (
	readOnly  = []string{http.MethodGet}
	readWrite = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
)

// tokenRoutes is everything a token may call: the configuration a provider
// or pipeline manages, read and written; credentials read only, so no secret
// passes through a token (or lands in a Terraform state); and who the token
// is. Policy reviews are a person's evidence, so not a token's.
var tokenRoutes = []tokenRoute{
	{"/api/v1/auth/me", readOnly},
	{"/api/v1/groups", readWrite},
	{"/api/v1/groups/", readWrite},
	{"/api/v1/targets", readWrite},
	{"/api/v1/targets/", readWrite},
	{"/api/v1/access-policies", readWrite},
	{"/api/v1/credentials", readOnly},
	{"/api/v1/credentials/", readOnly},
	{"/api/v1/admin/config/export", readOnly},
	{"/api/v1/admin/config/import", []string{http.MethodPost}},
}

// TokenAllowed reports whether a token may make a request of method to path.
func TokenAllowed(method, path string) bool {
	if method == http.MethodHead {
		method = http.MethodGet
	}
	// A policy by id, never its review.
	if rest, ok := strings.CutPrefix(path, "/api/v1/access-policies/"); ok {
		if rest == "" || strings.Contains(rest, "/") {
			return false
		}
		return slices.Contains(readWrite, method)
	}
	for _, rt := range tokenRoutes {
		prefix := strings.HasSuffix(rt.path, "/")
		match := (!prefix && path == rt.path) || (prefix && strings.HasPrefix(path, rt.path) && len(path) > len(rt.path))
		if match {
			return slices.Contains(rt.methods, method)
		}
	}
	return false
}

// bearer authenticates a request by its API token. It answers 401 for a
// token that does not stand (unknown, expired, revoked, or its owner no
// longer an active administrator) and 403 for a route a token may not call;
// it never falls back to the cookie.
func (m *Middleware) bearer(w http.ResponseWriter, r *http.Request, next http.Handler, secret string) {
	uid, tid, err := m.Tokens.Authenticate(r.Context(), secret, ClientIP(r))
	if errors.Is(err, ErrBadToken) {
		httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_token", "the API token is unknown, expired or revoked")
		return
	}
	if err != nil {
		m.unchecked(w, r, http.NotFoundHandler(), "api token lookup", err)
		return
	}
	u, err := m.Users.GetByID(r.Context(), uid)
	if errors.Is(err, user.ErrNotFound) || (err == nil && (u.IsBlocked() || !u.HasRole(user.RoleAdmin))) {
		httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_token", "the API token's owner is no longer an active administrator")
		return
	}
	if err != nil {
		m.unchecked(w, r, http.NotFoundHandler(), "api token user lookup", err)
		return
	}
	if !TokenAllowed(r.Method, r.URL.Path) {
		httpx.WriteError(w, r, http.StatusForbidden, "token_scope", "an API token reaches the configuration API only: groups, targets, policies, credentials (read) and the configuration file")
		return
	}
	// A session of its own kind: verified (a token has no second factor to
	// owe), never proved fresh (no step-up through a token), its id unlike
	// any browser session's.
	p := &Principal{Session: &Session{ID: "token:" + tid, UserID: uid, MFAVerified: true}, User: u, TokenID: tid}
	next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
}

// bearerSecret is the API token a request carries, or "".
func bearerSecret(r *http.Request) string {
	v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !strings.HasPrefix(v, TokenPrefix) {
		return ""
	}
	return strings.TrimSpace(v)
}
