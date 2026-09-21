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
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/idp"
)

const (
	stateCookie = "zanskar_oidc"
	stateTTL    = 10 * time.Minute
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
	// RequireMFA mirrors the deployment setting.
	RequireMFA bool
	// HTTPClient is used for discovery and token exchange; defaults to a
	// 10 second timeout client.
	HTTPClient *http.Client

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
		h.Log.Error("list providers", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
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
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure follows the session cookie setting
		Name: stateCookie, Value: sealed, Path: "/api/v1/auth/oidc/", HttpOnly: true,
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
	ip := auth.ClientIP(r)
	c, err := r.Cookie(stateCookie)
	if err != nil {
		h.fail(w, r, "", id, "state_missing", errors.New("no state cookie"))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/api/v1/auth/oidc/", HttpOnly: true, Secure: h.Sessions.SecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1}) // #nosec G124
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
	ident, err := identityFromToken(idt, cfg)
	if err != nil {
		h.fail(w, r, "", id, "claims_invalid", err)
		return
	}
	if len(cfg.AllowedDomains) > 0 && !domainAllowed(ident.Email, cfg.AllowedDomains) {
		h.fail(w, r, "", id, "domain_not_allowed", fmt.Errorf("email domain not allowed for %q", ident.Email))
		return
	}
	u, err := h.Provisioner.Resolve(r.Context(), op, ident)
	if err != nil {
		code := "provisioning_failed"
		if errors.Is(err, idp.ErrNotProvisioned) {
			code = "not_provisioned"
		}
		h.fail(w, r, "", id, code, err)
		return
	}

	mfa := "provider"
	verified := true
	if !cfg.SkipMFA {
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
		case h.RequireMFA:
			verified, mfa = false, "totp_enrollment"
		default:
			mfa = "none"
		}
	}
	token, sess, err := h.Sessions.Create(r.Context(), u.ID, ip, r.UserAgent(), verified)
	if err != nil {
		h.fail(w, r, u.ID, id, "internal", err)
		return
	}
	_ = h.Provisioner.Users.RecordLoginSuccess(r.Context(), u.ID)
	h.Sessions.SetCookie(w, token)
	h.record(r, audit.Actor{UserID: u.ID, IP: ip}.Event("user.login", "user", u.ID, audit.Success,
		map[string]string{"idp": id, "mfa": mfa, "session_id": sess.ID, "stage": map[bool]string{true: "complete", false: "password"}[verified]}))
	next := "/"
	if st.Next != "" {
		next = st.Next
	}
	if !verified {
		next = "/login?next=" + url.QueryEscape(next)
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// ---- helpers

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
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
}

func identityFromToken(idt *gooidc.IDToken, cfg *idp.OIDCConfig) (idp.Identity, error) {
	var all map[string]any
	if err := idt.Claims(&all); err != nil {
		return idp.Identity{}, err
	}
	var c claims
	_ = idt.Claims(&c)
	username, _ := all[cfg.UsernameClaim].(string)
	if username == "" {
		username = c.PreferredUsername
	}
	if username == "" && c.Email != "" {
		username = c.Email[:strings.IndexByte(c.Email+"@", '@')]
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return idp.Identity{}, errors.New("no usable username claim")
	}
	ident := idp.Identity{ExternalID: idt.Subject, Username: username, DisplayName: c.Name, Email: strings.ToLower(c.Email)}
	if cfg.GroupsClaim != "" {
		if raw, ok := all[cfg.GroupsClaim].([]any); ok {
			for _, g := range raw {
				if s, ok := g.(string); ok {
					ident.Groups = append(ident.Groups, s)
				}
			}
		}
	}
	return ident, nil
}

func domainAllowed(email string, domains []string) bool {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return false
	}
	d := strings.ToLower(email[at+1:])
	for _, allowed := range domains {
		if strings.EqualFold(strings.TrimSpace(allowed), d) {
			return true
		}
	}
	return false
}

func safeNext(next string) bool {
	return next != "" && strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") && !strings.ContainsAny(next, "\\\r\n")
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
	dot := strings.LastIndexByte(v, '.')
	if dot < 0 {
		return st, errors.New("bad state cookie")
	}
	body, err := base64.RawURLEncoding.DecodeString(v[:dot])
	if err != nil {
		return st, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(v[dot+1:])
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
	h.record(r, audit.Actor{UserID: userID, IP: auth.ClientIP(r)}.Event("user.login", "user", userID, audit.Failure,
		map[string]string{"idp": idpID, "reason": code}))
	http.Redirect(w, r, "/login?error="+url.QueryEscape(code), http.StatusFound)
}

func (h *Handler) record(r *http.Request, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if _, err := h.Audit.Record(r.Context(), e); err != nil {
		h.Log.Error("audit record failed", "action", e.Action, "err", err)
	}
}
