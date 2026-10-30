// SPDX-License-Identifier: Apache-2.0

// Package oidc signs users in through an OpenID Connect provider stored in
// the identity_providers table. The flow is authorization code with PKCE;
// the interim state lives in an HMAC-sealed cookie so nothing is stored
// server-side between start and callback.
package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/idp"
	"github.com/albatroxxx/zanskar/internal/keyring"
)

const (
	stateCookieName = "zanskar_oidc"
	stateTTL        = 10 * time.Minute
	// signedOutState is the state a provider echoes when it sends the
	// browser back to the callback after signing it out (LogoutURL).
	signedOutState = "signed-out"
)

// Handler serves the public provider list and the OIDC start/callback pair.
type Handler struct {
	Providers   *idp.Repo
	Provisioner *idp.Provisioner
	Sessions    *auth.Sessions
	Audit       *audit.Log
	Log         *slog.Logger
	// StateKey seals the interim state cookie (32 bytes recommended).
	StateKey []byte
	// BaseURL is the public origin (https://zanskar.example). Empty means
	// derive from the request: TLS state for the scheme, Host for the host.
	BaseURL string
	// MFAEnrolled reports whether the user has a confirmed authenticator.
	MFAEnrolled func(ctx context.Context, userID string) (bool, error)
	// RequireMFA mirrors the runtime setting, read at every sign-in; nil
	// means not required.
	RequireMFA func() bool
	// HTTPClient is used for discovery and token exchange; defaults to a
	// 10 second timeout client.
	HTTPClient *http.Client
	// Ring seals the ID token a session keeps for signing out at the
	// provider (ADR 0035); nil keeps none, and signing out then asks the
	// provider to confirm.
	Ring *keyring.Ring

	cache sync.Map // idp id -> *cached
}

type cached struct {
	updated  time.Time
	provider *gooidc.Provider
}

// Register mounts the routes.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/auth/providers", h.list)
	mux.HandleFunc("GET /api/v1/auth/oidc/{id}/start", h.start)
	mux.HandleFunc("GET /api/v1/auth/oidc/{id}/callback", h.callback)
}

type publicProvider struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Type idp.Type `json:"type"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	ps, err := h.Providers.List(r.Context(), true)
	if err != nil {
		httpx.Internal(w, r, h.Log, fmt.Errorf("list providers: %w", err))
		return
	}
	out := make([]publicProvider, 0, len(ps))
	for _, p := range ps {
		out = append(out, publicProvider{ID: p.ID, Name: p.Name, Type: p.Type})
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[publicProvider]{Items: out})
}

// state is what the sealed cookie carries between start and callback.
type state struct {
	IdP      string `json:"i"`
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x,omitempty"`
	Exp      int64  `json:"e"`
}

func (h *Handler) start(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	op, prov, cfg, err := h.open(r.Context(), id)
	if err != nil {
		h.fail(w, r, "", id, "provider_unavailable", err)
		return
	}
	st := state{IdP: id, State: randomString(), Nonce: randomString(), Verifier: oauth2.GenerateVerifier(), Exp: time.Now().Add(stateTTL).Unix()}
	if next := r.URL.Query().Get("next"); safeNext(next) {
		st.Next = next
	}
	sealed, err := h.seal(st)
	if err != nil {
		h.fail(w, r, "", id, "internal", err)
		return
	}
	name, path := h.stateCookie()
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure follows the session cookie setting
		Name: name, Value: sealed, Path: path, HttpOnly: true,
		Secure: h.Sessions.SecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: int(stateTTL / time.Second),
	})
	oc := h.oauthConfig(r, prov, op, cfg)
	authURL := oc.AuthCodeURL(st.State, oauth2.S256ChallengeOption(st.Verifier), gooidc.Nonce(st.Nonce))
	// authURL is built by the oauth2 library from the admin-configured issuer
	// discovery document, not from request input.
	http.Redirect(w, r, authURL, http.StatusFound) // #nosec G710
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Back from the provider's sign-out (LogoutURL): no code, no error, the
	// sign-out state. On to the sign-in page; nothing was attempted, so
	// nothing is recorded, and no session changes.
	if q := r.URL.Query(); q.Get("state") == signedOutState && q.Get("code") == "" && q.Get("error") == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	ip := auth.ClientIP(r)
	name, path := h.stateCookie()
	c, err := r.Cookie(name)
	if err != nil {
		h.fail(w, r, "", id, "state_missing", errors.New("no state cookie"))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: path, HttpOnly: true, Secure: h.Sessions.SecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1}) // #nosec G124
	st, err := h.unseal(c.Value)
	if err != nil || st.IdP != id || time.Now().Unix() > st.Exp || st.State == "" || st.State != r.URL.Query().Get("state") {
		h.fail(w, r, "", id, "state_invalid", errors.New("state mismatch or expired"))
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		h.fail(w, r, "", id, "provider_denied", fmt.Errorf("provider returned %s: %s", e, r.URL.Query().Get("error_description")))
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		h.fail(w, r, "", id, "code_missing", errors.New("no code"))
		return
	}
	op, prov, cfg, err := h.open(r.Context(), id)
	if err != nil {
		h.fail(w, r, "", id, "provider_unavailable", err)
		return
	}
	ctx := gooidc.ClientContext(r.Context(), h.client())
	oc := h.oauthConfig(r, prov, op, cfg)
	tok, err := oc.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		h.fail(w, r, "", id, "exchange_failed", err)
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		h.fail(w, r, "", id, "no_id_token", errors.New("token response had no id_token"))
		return
	}
	idt, err := prov.Verifier(&gooidc.Config{ClientID: cfg.ClientID}).Verify(ctx, rawID)
	if err != nil {
		h.fail(w, r, "", id, "id_token_invalid", err)
		return
	}
	if idt.Nonce != st.Nonce {
		h.fail(w, r, "", id, "nonce_mismatch", errors.New("nonce mismatch"))
		return
	}
	ident, emailTrusted, err := identityFromToken(idt, cfg)
	if err != nil {
		h.fail(w, r, "", id, "claims_invalid", err)
		return
	}
	if code, err := admit(ident, emailTrusted, cfg); err != nil {
		h.fail(w, r, "", id, code, err)
		return
	}
	res, err := h.Provisioner.Resolve(r.Context(), op, ident)
	if err != nil {
		code := "provisioning_failed"
		switch {
		case errors.Is(err, idp.ErrNotProvisioned):
			code = "not_provisioned"
		case errors.Is(err, idp.ErrAccountConflict):
			code = "account_conflict"
		}
		h.fail(w, r, "", id, code, err)
		return
	}
	u := res.User
	for _, e := range res.Events(ip, op, ident) {
		h.record(r, e)
	}

	// The provider's sign-in is the second factor (ADR 0035), unless the
	// provider is marked as doing none and Zanskar asks for its own.
	mfa := "provider"
	verified := true
	if cfg.ZanskarMFA {
		enrolled := false
		if h.MFAEnrolled != nil {
			if enrolled, err = h.MFAEnrolled(r.Context(), u.ID); err != nil {
				h.fail(w, r, u.ID, id, "internal", err)
				return
			}
		}
		switch {
		case enrolled:
			verified, mfa = false, "totp_pending"
		case h.RequireMFA != nil && h.RequireMFA():
			verified, mfa = false, "totp_enrollment"
		default:
			mfa = "none"
		}
	}
	auth.ReplaceSession(r, h.Sessions, h.Audit, h.Log)
	token, sess, err := h.Sessions.Create(r.Context(), u.ID, ip, r.UserAgent(), verified)
	if err != nil {
		h.fail(w, r, u.ID, id, "internal", err)
		return
	}
	// Only a sign-in that completes clears the account's failure count, which
	// wrong passwords and wrong authenticator codes share (M7). One that still
	// owes the code must not hand out a fresh set of guesses at it; the code
	// step clears the count when it succeeds.
	if verified {
		_ = h.Provisioner.Users.RecordLoginSuccess(r.Context(), u.ID)
	}
	// The session remembers the provider and its ID token so that signing
	// out ends the provider's session too (ADR 0035). Failing to costs only
	// that, so the sign-in goes on.
	if err := h.rememberProvider(r.Context(), sess.ID, op.ID, rawID); err != nil {
		h.Log.Warn("oidc: keep the provider for sign-out", "idp", id, "err", err)
	}
	h.Sessions.SetCookie(w, token)
	h.record(r, audit.Actor{UserID: u.ID, IP: ip}.Event(audit.UserLogin, "user", u.ID, audit.Success,
		map[string]string{"idp": id, "mfa": mfa, "session_id": sess.ID, "stage": map[bool]string{true: "complete", false: "password"}[verified]}))
	// The cookie is sealed, so Next is what start accepted; checking it again
	// costs nothing and covers a cookie sealed under an older rule.
	next := "/"
	if safeNext(st.Next) {
		next = st.Next
	}
	if !verified {
		next = "/login?next=" + url.QueryEscape(next)
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// rememberProvider records on the session the provider it signed in
// through and the ID token, sealed to that session.
func (h *Handler) rememberProvider(ctx context.Context, sessionID, idpID, rawIDToken string) error {
	var (
		enc []byte
		ver int
	)
	if h.Ring != nil {
		var err error
		if enc, ver, err = h.Ring.Encrypt(keyring.AAD("auth_sessions", sessionID), []byte(rawIDToken)); err != nil {
			return err
		}
	}
	return h.Sessions.SetProvider(ctx, sessionID, idpID, enc, ver)
}

// LogoutURL is where the browser goes once a session has signed out, when
// it signed in through a provider (ADR 0035): the provider's
// end_session_endpoint (OpenID Connect RP-Initiated Logout) with the
// session's ID token as id_token_hint and the client id. The way back,
// post_logout_redirect_uri, is the provider's own callback with the
// sign-out state, which the callback sends on to the sign-in page: a
// provider accepts only an address it has registered, and refuses the
// whole sign-out otherwise (Keycloak answers "Invalid redirect uri" and
// keeps its session), while the callback is registered already, or no
// sign-in would work. It is empty when the session signed in some other
// way, the provider keeps its session (keep_provider_session), or it
// publishes no https end_session_endpoint. It never stands in the way of
// signing out: a problem is logged and the answer is empty.
func (h *Handler) LogoutURL(r *http.Request, sessionID string) string {
	ctx := r.Context()
	idpID, enc, ver, err := h.Sessions.Provider(ctx, sessionID)
	if err != nil || idpID == "" {
		return ""
	}
	op, prov, cfg, err := h.open(ctx, idpID)
	if err != nil {
		h.Log.Warn("oidc: sign out at the provider", "idp", idpID, "err", err)
		return ""
	}
	if cfg.KeepProviderSession {
		return ""
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := prov.Claims(&meta); err != nil || meta.EndSession == "" {
		return ""
	}
	u, err := url.Parse(meta.EndSession)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		h.Log.Warn("oidc: provider's end_session_endpoint is not an https URL", "idp", idpID)
		return ""
	}
	q := u.Query()
	q.Set("client_id", cfg.ClientID)
	q.Set("post_logout_redirect_uri", h.baseURL(r)+"/api/v1/auth/oidc/"+op.ID+"/callback")
	q.Set("state", signedOutState)
	if enc != nil && h.Ring != nil {
		if raw, err := h.Ring.Decrypt(keyring.AAD("auth_sessions", sessionID), enc, ver); err == nil {
			q.Set("id_token_hint", string(raw))
		} else {
			h.Log.Warn("oidc: unseal the session's ID token", "idp", op.ID, "err", err)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// ---- helpers

// stateCookie names the state cookie and its path: with the __Host- prefix
// and Path=/ when cookies are Secure, so that a sibling subdomain cannot
// plant a sealed state of its own and finish its authorization code in
// this browser (S1 L6); the bare name on its own path otherwise.
func (h *Handler) stateCookie() (name, path string) {
	if h.Sessions.SecureCookie {
		return "__Host-" + stateCookieName, "/"
	}
	return stateCookieName, "/api/v1/auth/oidc/"
}

func (h *Handler) open(ctx context.Context, id string) (*idp.Opened, *gooidc.Provider, *idp.OIDCConfig, error) {
	op, err := h.Providers.Open(ctx, id)
	if err != nil {
		return nil, nil, nil, err
	}
	if !op.Enabled || op.Type != idp.TypeOIDC || op.Config.OIDC == nil {
		return nil, nil, nil, errors.New("provider is not an enabled oidc provider")
	}
	if c, ok := h.cache.Load(id); ok {
		if cc := c.(*cached); cc.updated.Equal(op.UpdatedAt) {
			return op, cc.provider, op.Config.OIDC, nil
		}
	}
	dctx, cancel := context.WithTimeout(gooidc.ClientContext(ctx, h.client()), 10*time.Second)
	defer cancel()
	prov, err := gooidc.NewProvider(dctx, op.Config.OIDC.Issuer)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("discovery: %w", err)
	}
	h.cache.Store(id, &cached{updated: op.UpdatedAt, provider: prov})
	return op, prov, op.Config.OIDC, nil
}

func (h *Handler) client() *http.Client {
	if h.HTTPClient != nil {
		return h.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (h *Handler) oauthConfig(r *http.Request, prov *gooidc.Provider, op *idp.Opened, cfg *idp.OIDCConfig) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     prov.Endpoint(),
		RedirectURL:  h.baseURL(r) + "/api/v1/auth/oidc/" + op.ID + "/callback",
		Scopes:       cfg.Scopes,
	}
}

func (h *Handler) baseURL(r *http.Request) string {
	if h.BaseURL != "" {
		return strings.TrimRight(h.BaseURL, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

type claims struct {
	Email             string `json:"email"`
	EmailVerified     any    `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
}

// identityFromToken reads who signed in. emailTrusted reports whether the
// address may stand for the person: the provider verified it, or never says
// and is marked TrustEmail. An address the provider says is unverified is
// dropped, and only a trusted one makes a username when no claim gives one.
func identityFromToken(idt *gooidc.IDToken, cfg *idp.OIDCConfig) (ident idp.Identity, emailTrusted bool, err error) {
	var all map[string]any
	if err := idt.Claims(&all); err != nil {
		return idp.Identity{}, false, err
	}
	if idt.Subject == "" {
		return idp.Identity{}, false, errors.New("no subject")
	}
	return identityFromClaims(idt.Subject, all, cfg)
}

// identityFromClaims is identityFromToken over claims already read: the
// directory sync (KeycloakDirectory) builds them from the admin API, so that
// a person listed there is asserted exactly as their sign-in would be.
func identityFromClaims(subject string, all map[string]any, cfg *idp.OIDCConfig) (ident idp.Identity, emailTrusted bool, err error) {
	var c claims
	if raw, err := json.Marshal(all); err == nil {
		_ = json.Unmarshal(raw, &c)
	}
	email := strings.ToLower(strings.TrimSpace(c.Email))
	verified, said := emailVerified(c.EmailVerified)
	if said && !verified {
		email = ""
	}
	emailTrusted = email != "" && (verified || (!said && cfg.TrustEmail))
	username, _ := all[cfg.UsernameClaim].(string)
	if username == "" {
		username = c.PreferredUsername
	}
	if username == "" && emailTrusted {
		username = email[:strings.IndexByte(email+"@", '@')]
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return idp.Identity{}, false, errors.New("no usable username claim")
	}
	ident = idp.Identity{ExternalID: subject, Username: username, DisplayName: c.Name, Email: email}
	if cfg.GroupsClaim != "" {
		if raw, ok := all[cfg.GroupsClaim].([]any); ok {
			for _, g := range raw {
				if s, ok := g.(string); ok {
					ident.Groups = append(ident.Groups, s)
				}
			}
		}
	}
	return ident, emailTrusted, nil
}

// admit applies the provider's own gate on who may sign in: with allowed
// email domains, an address the provider vouches for (emailTrusted) in one
// of them. It answers the failure code a sign-in reports.
func admit(ident idp.Identity, emailTrusted bool, cfg *idp.OIDCConfig) (string, error) {
	if len(cfg.AllowedDomains) == 0 {
		return "", nil
	}
	// The gate means something only for an address the provider vouches
	// for: on one where people edit their own, anyone could type in an
	// allowed domain.
	if !emailTrusted {
		return "email_unverified", errors.New("the provider has not verified the email address")
	}
	if !domainAllowed(ident.Email, cfg.AllowedDomains) {
		return "domain_not_allowed", fmt.Errorf("email domain not allowed for %q", ident.Email)
	}
	return "", nil
}

// emailVerified reads the email_verified claim, a boolean or the string some
// providers send instead. said is false when the claim is absent or neither.
func emailVerified(v any) (verified, said bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		if b, err := strconv.ParseBool(x); err == nil {
			return b, true
		}
	}
	return false, false
}

func domainAllowed(email string, domains []string) bool {
	_, after, ok := strings.CutLast(email, "@")
	if !ok {
		return false
	}
	d := strings.ToLower(after)
	for _, allowed := range domains {
		if strings.EqualFold(strings.TrimSpace(allowed), d) {
			return true
		}
	}
	return false
}

// safeNext reports whether next may be used as the post-login redirect. Only a
// path on this origin qualifies: it starts with exactly one "/", carries no
// scheme, host or userinfo once parsed, is already clean (no "." or ".."
// segments; a single trailing slash is fine), and contains no control
// character or backslash. The control-character rule is what keeps the check
// honest: browsers strip ASCII tab, CR and LF from a URL before parsing it,
// so "/" + TAB + "/evil.example" becomes the scheme-relative "//evil.example",
// and http.Redirect writes a value Go's parser rejects verbatim, with no
// cleaning. Browsers also read "\" as "/" in http URLs and skip extra slashes
// after the scheme, so "/\evil" and "///evil" are refused on the raw string
// rather than on the parsed path. Percent-encoded characters need no rule of
// their own: the browser keeps them encoded, so "%09" or "%2F" in a path can
// never turn into a second "/".
func safeNext(next string) bool {
	// Exactly one leading "/": a second "/" or "\" makes the rest a host.
	if len(next) == 0 || next[0] != '/' || (len(next) > 1 && (next[1] == '/' || next[1] == '\\')) {
		return false
	}
	for _, r := range next {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return false
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Opaque != "" || u.User != nil || u.Host != "" {
		return false
	}
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return false
	}
	if clean := path.Clean(u.Path); u.Path != clean && u.Path != clean+"/" {
		return false
	}
	return true
}

func randomString() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *Handler) seal(st state) (string, error) {
	if len(h.StateKey) == 0 {
		return "", errors.New("oidc: StateKey not configured")
	}
	body, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, h.StateKey)
	mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (h *Handler) unseal(v string) (state, error) {
	var st state
	before, after, ok := strings.CutLast(v, ".")
	if !ok {
		return st, errors.New("bad state cookie")
	}
	body, err := base64.RawURLEncoding.DecodeString(before)
	if err != nil {
		return st, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(after)
	if err != nil {
		return st, err
	}
	mac := hmac.New(sha256.New, h.StateKey)
	mac.Write(body)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return st, errors.New("state signature invalid")
	}
	return st, json.Unmarshal(body, &st)
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, userID, idpID, code string, err error) {
	h.Log.Warn("oidc login failed", "idp", idpID, "code", code, "err", err)
	h.record(r, audit.Actor{UserID: userID, IP: auth.ClientIP(r)}.Event(audit.UserLogin, "user", userID, audit.Failure,
		map[string]string{"idp": idpID, "reason": code}))
	http.Redirect(w, r, "/login?error="+url.QueryEscape(code), http.StatusFound)
}

func (h *Handler) record(r *http.Request, e audit.Event) {
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, e)
}
