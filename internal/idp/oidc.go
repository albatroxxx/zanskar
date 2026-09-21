// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCFlow runs the OpenID Connect authorization-code flow for one provider.
// Build it once per sign-in (or cache per provider); NewOIDCFlow performs
// network discovery against the issuer.
type OIDCFlow struct {
	cfg      *OIDCConfig
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

// NewOIDCFlow discovers the issuer's endpoints and prepares the flow. The
// redirectURL must exactly match one registered with the provider and is the
// URL the browser is sent back to (Zanskar's /auth/oidc/{id}/callback).
func NewOIDCFlow(ctx context.Context, o *OIDCConfig, redirectURL string) (*OIDCFlow, error) {
	if o == nil {
		return nil, fmt.Errorf("%w: nil oidc config", ErrInvalidInput)
	}
	provider, err := oidc.NewProvider(ctx, o.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery for %s: %w", o.Issuer, err)
	}
	scopes := o.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	return &OIDCFlow{
		cfg:      o,
		verifier: provider.Verifier(&oidc.Config{ClientID: o.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     o.ClientID,
			ClientSecret: o.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       scopes,
		},
	}, nil
}

// AuthCodeURL builds the redirect URL that starts the login. state is an
// opaque anti-CSRF value the caller stores and re-checks on callback; nonce
// binds the returned id_token to this request and is verified in Exchange.
func (f *OIDCFlow) AuthCodeURL(state, nonce string) string {
	return f.oauth.AuthCodeURL(state, oidc.Nonce(nonce))
}

// Exchange trades the authorization code for tokens, verifies the id_token's
// signature, audience, expiry and nonce, and returns the asserted Identity.
// Tokens are never logged.
func (f *OIDCFlow) Exchange(ctx context.Context, code, nonce string) (Identity, error) {
	tok, err := f.oauth.Exchange(ctx, code)
	if err != nil {
		return Identity{}, fmt.Errorf("oidc: code exchange failed: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return Identity{}, errors.New("oidc: response contained no id_token")
	}
	idToken, err := f.verifier.Verify(ctx, rawID)
	if err != nil {
		return Identity{}, fmt.Errorf("oidc: id_token verification failed: %w", err)
	}
	if idToken.Nonce != nonce {
		return Identity{}, errors.New("oidc: id_token nonce does not match the request")
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("oidc: reading claims: %w", err)
	}
	// The subject is authoritative regardless of what the claims map holds.
	if claims == nil {
		claims = map[string]any{}
	}
	claims["sub"] = idToken.Subject
	return identityFromClaims(f.cfg, claims)
}

// identityFromClaims maps verified id_token claims to an Identity and enforces
// the domain restriction. It is separated from the network flow so it can be
// tested directly.
func identityFromClaims(o *OIDCConfig, claims map[string]any) (Identity, error) {
	sub := claimString(claims, "sub")
	if sub == "" {
		return Identity{}, errors.New("oidc: id_token has no subject")
	}
	email := claimString(claims, "email")
	if len(o.AllowedDomains) > 0 {
		if !domainAllowed(email, o.AllowedDomains) {
			return Identity{}, fmt.Errorf("oidc: sign-in is restricted to %s", strings.Join(o.AllowedDomains, ", "))
		}
	}

	username := ""
	if o.UsernameClaim != "" {
		username = claimString(claims, o.UsernameClaim)
	}
	if username == "" {
		username = claimString(claims, "preferred_username")
	}
	if username == "" && email != "" {
		username = emailLocalPart(email)
	}

	return Identity{
		ExternalID:  sub,
		Username:    username,
		DisplayName: claimString(claims, "name"),
		Email:       email,
		Groups:      claimStrings(claims, o.GroupsClaim),
	}, nil
}

// RandomState returns a 32-byte URL-safe random string for the OAuth state.
func RandomState() (string, error) { return randomToken() }

// RandomNonce returns a 32-byte URL-safe random string for the OIDC nonce.
func RandomNonce() (string, error) { return randomToken() }

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func claimString(claims map[string]any, key string) string {
	if key == "" {
		return ""
	}
	if v, ok := claims[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// claimStrings reads a claim that should be a JSON array of strings. A single
// string value is accepted as a one-element list, which some providers emit.
func claimStrings(claims map[string]any, key string) []string {
	if key == "" {
		return nil
	}
	switch v := claims[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}

func domainAllowed(email string, domains []string) bool {
	dom := emailDomain(email)
	if dom == "" {
		return false
	}
	for _, d := range domains {
		if strings.EqualFold(dom, strings.TrimSpace(d)) {
			return true
		}
	}
	return false
}

func emailDomain(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return email[at+1:]
}

func emailLocalPart(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at <= 0 {
		return email
	}
	return email[:at]
}
