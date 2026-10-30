// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/idp"
	"github.com/albatroxxx/zanskar/internal/user"
)

// signOut posts to /auth/logout with the session cookies and returns the
// status and the redirect the answer names.
func signOut(t *testing.T, e *env, cookies []*http.Cookie) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.app.URL+"/api/v1/auth/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]string
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res.StatusCode, body["redirect"]
}

func signedIn(t *testing.T, e *env, cookies []*http.Cookie) bool {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.app.URL+"/api/v1/auth/me", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode == http.StatusOK
}

func kcConfig() idp.Config {
	return idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s"}, AutoProvision: true}
}

// TestSignOutEndsTheProviderSession (ADR 0035): signing out of a session
// that came from the provider revokes it and names the provider's
// end_session_endpoint, keeping the query the provider published, with the
// session's ID token as id_token_hint, the client id, and the sign-in page
// to come back to. The token is stored sealed, and the audit event says the
// provider was asked too.
func TestSignOutEndsTheProviderSession(t *testing.T) {
	f := newFakeIdP(t)
	f.claims = map[string]any{"preferred_username": "kim", "email": "kim@corp.example"}
	e, id := newEnv(t, f, kcConfig())
	_, _, cookies := drive(t, e, f, id)
	if !signedIn(t, e, cookies) {
		t.Fatal("not signed in after the provider's sign-in")
	}
	issued := f.idToken

	var stored []byte
	if err := e.db.QueryRowContext(context.Background(), `SELECT id_token_enc FROM auth_sessions WHERE idp_id IS NOT NULL`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) == 0 || strings.Contains(string(stored), issued[:20]) {
		t.Fatalf("the ID token must be stored sealed: %d bytes", len(stored))
	}

	status, to := signOut(t, e, cookies)
	if status != http.StatusOK || to == "" {
		t.Fatalf("sign-out: %d redirect %q", status, to)
	}
	u, err := url.Parse(to)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if !strings.HasPrefix(to, f.srv.URL+"/logout?") || q.Get("kc") != "1" {
		t.Fatalf("redirect %s: want the provider's end_session_endpoint with its own query", to)
	}
	if q.Get("id_token_hint") != issued || q.Get("client_id") != "cid" || q.Get("post_logout_redirect_uri") != e.app.URL+"/login" {
		t.Fatalf("redirect query: %v", q)
	}
	if signedIn(t, e, cookies) {
		t.Fatal("the session must be revoked")
	}
	events, _, err := e.h.Audit.List(context.Background(), audit.Filter{Action: audit.UserLogout, Limit: 5})
	if err != nil || len(events) != 1 || !strings.Contains(string(events[0].Details), `"provider_sign_out":"true"`) {
		t.Fatalf("logout event: %v %v", events, err)
	}
}

// TestSignOutStaysLocal: no redirect for a provider that keeps its session
// (keep_provider_session), one that publishes no end_session_endpoint or one
// that is not https, a deleted provider, or a session that never came from a
// provider. Each is still signed out.
func TestSignOutStaysLocal(t *testing.T) {
	cases := []struct {
		name       string
		endSession string
		keep       bool
	}{
		{"provider keeps its session", "", true},
		{"no end_session_endpoint", "-", false},
		{"plain http end_session_endpoint", "http://idp.example/logout", false},
		{"javascript end_session_endpoint", "javascript:alert(1)", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIdP(t)
			f.endSession = tc.endSession
			f.claims = map[string]any{"preferred_username": "lee", "email": "lee@corp.example"}
			cfg := kcConfig()
			cfg.OIDC.KeepProviderSession = tc.keep
			e, id := newEnv(t, f, cfg)
			_, _, cookies := drive(t, e, f, id)
			if status, to := signOut(t, e, cookies); status != http.StatusOK || to != "" {
				t.Fatalf("sign-out: %d redirect %q, want none", status, to)
			}
			if signedIn(t, e, cookies) {
				t.Fatal("the session must be revoked")
			}
		})
	}

	t.Run("provider deleted", func(t *testing.T) {
		f := newFakeIdP(t)
		f.claims = map[string]any{"preferred_username": "max", "email": "max@corp.example"}
		e, id := newEnv(t, f, kcConfig())
		_, _, cookies := drive(t, e, f, id)
		if err := e.repo.Delete(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		if status, to := signOut(t, e, cookies); status != http.StatusOK || to != "" {
			t.Fatalf("sign-out: %d redirect %q, want none", status, to)
		}
	})

	t.Run("password session", func(t *testing.T) {
		f := newFakeIdP(t)
		e, _ := newEnv(t, f, kcConfig())
		u := &user.User{Username: "pat", DisplayName: "pat", Roles: []user.Role{user.RoleUser}}
		if err := e.users.Create(context.Background(), u); err != nil {
			t.Fatal(err)
		}
		token, _, err := e.sessions.Create(context.Background(), u.ID, "127.0.0.1", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		cookies := []*http.Cookie{{Name: e.sessions.CookieName(), Value: token}}
		if status, to := signOut(t, e, cookies); status != http.StatusOK || to != "" {
			t.Fatalf("sign-out: %d redirect %q, want none", status, to)
		}
	})
}

// TestSessionTokenIsBoundToItsSession: the sealed token is bound to the
// session it was issued for. Copied onto another session's row it does not
// open, and that session signs out with the client id alone, which a
// provider answers by asking the person to confirm, never with someone
// else's token.
func TestSessionTokenIsBoundToItsSession(t *testing.T) {
	f := newFakeIdP(t)
	f.claims = map[string]any{"preferred_username": "ned", "email": "ned@corp.example"}
	e, id := newEnv(t, f, kcConfig())
	drive(t, e, f, id)
	_, _, second := drive(t, e, f, id)
	ctx := context.Background()
	db := e.db
	var ids []string
	rows, err := db.QueryContext(ctx, `SELECT id FROM auth_sessions WHERE idp_id IS NOT NULL ORDER BY created_at`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, s)
	}
	rows.Close()
	if len(ids) != 2 {
		t.Fatalf("sessions: %v", ids)
	}
	if _, err := db.ExecContext(ctx, db.Rebind(`UPDATE auth_sessions SET id_token_enc = (SELECT id_token_enc FROM auth_sessions WHERE id = ?), key_version = (SELECT key_version FROM auth_sessions WHERE id = ?) WHERE id = ?`), ids[0], ids[0], ids[1]); err != nil {
		t.Fatal(err)
	}
	_, to := signOut(t, e, second)
	q := mustQuery(t, to)
	if q.Get("id_token_hint") != "" || q.Get("client_id") != "cid" {
		t.Fatalf("a token sealed for another session must not be used: %v", q)
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		t.Fatalf("redirect %q: %v", raw, err)
	}
	return u.Query()
}
