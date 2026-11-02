// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestConnectionTestReportsProviderSignOut (ADR 0035): the connection test
// says whether signing out can end the provider's session too, which needs
// an https end_session_endpoint in discovery; Google publishes none.
func TestConnectionTestReportsProviderSignOut(t *testing.T) {
	for _, tc := range []struct {
		name       string
		endSession string
		want       bool
	}{
		{"published", "/logout", true},
		{"not published (Google)", "", false},
		{"not https", "http://idp.example/logout", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				doc := map[string]any{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/auth", "token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/jwks"}
				switch {
				case tc.endSession == "/logout":
					doc["end_session_endpoint"] = srv.URL + "/logout"
				case tc.endSession != "":
					doc["end_session_endpoint"] = tc.endSession
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(doc)
			}))
			defer srv.Close()
			e := newEnv(t)
			e.h.HTTPClient = srv.Client()
			code, out, raw := e.do(t, "POST", "/api/v1/identity-providers", map[string]any{"name": "p", "type": "oidc", "config": map[string]any{
				"oidc": map[string]any{"issuer": srv.URL, "client_id": "cid", "client_secret": "s"}}})
			if code != http.StatusCreated {
				t.Fatalf("create: %d %s", code, raw)
			}
			code, res, raw := e.do(t, "POST", "/api/v1/identity-providers/"+out["id"].(string)+"/test", nil)
			if code != http.StatusOK || res["status"] != "ok" || res["provider_sign_out"] != tc.want {
				t.Fatalf("test: %d %s", code, raw)
			}
		})
	}
}

// TestConnectionTestSaysWhyInPlainWords: a provider the gateway cannot
// reach is reported by host with what happened, as the sync reports it,
// not as the chain of calls the failure came through (2026-11-02).
func TestConnectionTestSaysWhyInPlainWords(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	e := newEnv(t)
	code, out, raw := e.do(t, "POST", "/api/v1/identity-providers", map[string]any{"name": "p", "type": "oidc", "config": map[string]any{
		"oidc": map[string]any{"issuer": "https://" + closed + "/realms/zanskar", "client_id": "cid", "client_secret": "s"}}})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	code, res, raw := e.do(t, "POST", "/api/v1/identity-providers/"+out["id"].(string)+"/test", nil)
	want := "could not reach " + closed + ": it refused the connection"
	if code != http.StatusBadGateway || res["message"] != want {
		t.Fatalf("test: %d %s\nwant message %q", code, raw, want)
	}
}
