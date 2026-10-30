// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/albatroxxx/zanskar/internal/idp"
)

// KeycloakDirectory lists a Keycloak realm's users for the user sync
// (ADR 0035), through the realm's admin API, as the provider's own client:
// a client-credentials token for the client's service account, which needs
// the realm-management role view-users and nothing more. Each user becomes
// the Identity their sign-in would assert (identityFromClaims, admit), so
// the sync and a sign-in agree on who someone is; the subject of Keycloak's
// ID token is the user's id.
type KeycloakDirectory struct {
	// HTTPClient reaches Keycloak; defaults to a 30 second timeout client.
	HTTPClient *http.Client
	// PageSize is how many users one request asks for; default 200.
	PageSize int
}

// maxDirectoryUsers bounds a listing, and maxPageBytes one page of it.
const (
	maxDirectoryUsers = 200_000
	maxPageBytes      = 16 << 20
)

type keycloakUser struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"emailVerified"`
	FirstName     string `json:"firstName"`
	LastName      string `json:"lastName"`
	Enabled       bool   `json:"enabled"`
	// ServiceAccountClientID is set on a client's service-account user,
	// which no person signs in as.
	ServiceAccountClientID string `json:"serviceAccountClientId"`
}

// Users lists the realm. The count is read before and after the pages: a
// realm that changed while it was read may have shifted someone across a
// page boundary, and a person missing from the list would be taken for one
// who left, so a listing that does not hold still is an error.
func (d *KeycloakDirectory) Users(ctx context.Context, p *idp.Opened) ([]idp.Identity, error) {
	cfg := p.Config.OIDC
	if cfg == nil {
		return nil, errors.New("not an OIDC provider")
	}
	base, _, err := idp.KeycloakRealm(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	hc := d.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	cctx := gooidc.ClientContext(ctx, hc)
	prov, err := gooidc.NewProvider(cctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	cc := clientcredentials.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, TokenURL: prov.Endpoint().TokenURL}
	api := cc.Client(cctx)

	for range 2 {
		before, err := d.count(ctx, api, base)
		if err != nil {
			return nil, err
		}
		list, err := d.list(ctx, api, base, before)
		if err != nil {
			return nil, err
		}
		after, err := d.count(ctx, api, base)
		if err != nil {
			return nil, err
		}
		if before == after {
			return identities(list, cfg), nil
		}
	}
	return nil, errors.New("the realm's users changed while they were listed; the next run tries again")
}

func (d *KeycloakDirectory) count(ctx context.Context, api *http.Client, base string) (int, error) {
	var n int
	if err := get(ctx, api, base+"/users/count", &n); err != nil {
		return 0, err
	}
	return n, nil
}

func (d *KeycloakDirectory) list(ctx context.Context, api *http.Client, base string, expect int) ([]keycloakUser, error) {
	size := d.PageSize
	if size <= 0 {
		size = 200
	}
	var out []keycloakUser
	for first := 0; ; first += size {
		if first > maxDirectoryUsers {
			return nil, fmt.Errorf("the realm lists more than %d users", maxDirectoryUsers)
		}
		q := url.Values{"first": {strconv.Itoa(first)}, "max": {strconv.Itoa(size)}, "briefRepresentation": {"true"}}
		var page []keycloakUser
		if err := get(ctx, api, base+"/users?"+q.Encode(), &page); err != nil {
			return nil, err
		}
		out = append(out, page...)
		if len(page) < size {
			break
		}
	}
	if len(out) < expect {
		return nil, fmt.Errorf("the realm counts %d users but listed %d", expect, len(out))
	}
	return out, nil
}

// identities keeps the enabled people and asserts each as their sign-in
// would. One their sign-in would refuse (no usable username, or an address
// outside the allowed domains) is left out, as if not in the directory.
func identities(list []keycloakUser, cfg *idp.OIDCConfig) []idp.Identity {
	out := make([]idp.Identity, 0, len(list))
	for _, u := range list {
		if !u.Enabled || u.ID == "" || u.ServiceAccountClientID != "" {
			continue
		}
		claims := map[string]any{"sub": u.ID, "preferred_username": u.Username, "email": u.Email, "email_verified": u.EmailVerified}
		if name := strings.TrimSpace(u.FirstName + " " + u.LastName); name != "" {
			claims["name"] = name
		}
		ident, trusted, err := identityFromClaims(u.ID, claims, cfg)
		if err != nil {
			continue
		}
		if _, err := admit(ident, trusted, cfg); err != nil {
			continue
		}
		out = append(out, ident)
	}
	return out
}

// get reads one admin API answer into v, naming the role a refusal means.
func get(ctx context.Context, api *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := api.Do(req)
	if err != nil {
		return fmt.Errorf("keycloak admin API: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	switch {
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		return fmt.Errorf("keycloak admin API refused the client (HTTP %d): turn on its service account and give it the realm-management role view-users", res.StatusCode)
	case res.StatusCode != http.StatusOK:
		return fmt.Errorf("keycloak admin API: HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxPageBytes+1))
	if err != nil {
		return fmt.Errorf("keycloak admin API: %w", err)
	}
	if len(body) > maxPageBytes {
		return errors.New("keycloak admin API: answer too large")
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("keycloak admin API: %w", err)
	}
	return nil
}
