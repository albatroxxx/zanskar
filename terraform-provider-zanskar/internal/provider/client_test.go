// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func regexpMust(s string) *regexp.Regexp { return regexp.MustCompile(s) }

// The client refuses what would leak a token, and reads the gateway's
// refusals into an error that says why.
func TestNewClientRefuses(t *testing.T) {
	for _, c := range []struct{ url, token, want string }{
		{"http://zanskar.example.com", "zapi_x", "https://"},
		{"ftp://zanskar.example.com", "zapi_x", "gateway's address"},
		{"zanskar.example.com", "zapi_x", "gateway's address"},
		{"https://zanskar.example.com", "zscim_x", "API token"},
		{"https://zanskar.example.com", "", "API token"},
		{"https://zanskar.example.com", "zapi_x", ""},
		{"http://127.0.0.1:8080", "zapi_x", ""},
	} {
		_, err := NewClient(c.url, c.token, "", "test")
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Fatalf("%s %s: %v, want %q", c.url, c.token, err, c.want)
		}
	}
	if _, err := NewClient("https://zanskar.example.com", "zapi_x", "not a pem", "test"); err == nil {
		t.Fatal("a ca_pem with no certificate was taken")
	}
}

func TestClientSendsTheTokenAndReadsRefusals(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer zapi_good" || !strings.HasPrefix(r.Header.Get("User-Agent"), "terraform-provider-zanskar/") {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "invalid_token", "message": "the API token is unknown"})
			return
		}
		switch r.URL.Path {
		case "/api/v1/groups/gone":
			w.WriteHeader(404)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "not_found", "message": "group not found"})
		case "/api/v1/groups":
			if r.URL.Query().Get("cursor") == "" {
				_ = json.NewEncoder(w).Encode(map[string]any{"items": []apiGroup{{ID: "g1", Name: "a"}}, "next_cursor": "c2"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []apiGroup{{ID: "g2", Name: "b"}}})
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	c, err := NewClient(srv.URL, "zapi_good", "", "test")
	if err != nil {
		t.Fatal(err)
	}
	err = c.do(ctx, http.MethodGet, "/groups/gone", nil, nil)
	if !IsNotFound(err) || !strings.Contains(err.Error(), "group not found") {
		t.Fatalf("a 404: %v", err)
	}
	// A name on the second page is found.
	g, err := findByName(ctx, c, "/groups", "b", func(g apiGroup) string { return g.Name })
	if err != nil || g == nil || g.ID != "g2" {
		t.Fatalf("second page: %+v %v", g, err)
	}
	if g, err := findByName(ctx, c, "/groups", "zz", func(g apiGroup) string { return g.Name }); err != nil || g != nil {
		t.Fatalf("absent: %+v %v", g, err)
	}
	bad, _ := NewClient(srv.URL, "zapi_bad", "", "test")
	err = bad.do(ctx, http.MethodGet, "/groups", nil, nil)
	if err == nil || IsNotFound(err) || !strings.Contains(err.Error(), "invalid_token") {
		t.Fatalf("a refused token: %v", err)
	}
}
