// SPDX-License-Identifier: Apache-2.0

package tlscert

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestAppsCertificate: the applications certificate (ADR 0033) answers a
// handshake for a host under the apps domain and nothing else; the console's
// certificate answers everything else; an upload must name *.<domain>;
// AppsReady names what is missing; a reloaded manager serves the stored one.
func TestAppsCertificate(t *testing.T) {
	ctx := context.Background()
	repo, _ := newRepo(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	domain := "apps.example.test"
	m := &Manager{Repo: repo, Log: log, Hosts: []string{"gw.example.test"}, AppsDomain: func() string { return domain }}
	if err := m.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Apps(); ok {
		t.Fatal("an applications certificate exists before any upload")
	}
	if err := m.AppsReady(domain); err == nil || !strings.Contains(err.Error(), "*."+domain) {
		t.Fatalf("AppsReady with no certificate: %v", err)
	}
	// Without one, an application host gets the console's certificate.
	console := m.Active()
	got, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "wiki." + domain})
	if err != nil || describe("", got.Leaf, "").Fingerprint != console.Fingerprint {
		t.Fatalf("app host without an apps certificate: %v", err)
	}

	wrong, wrongKey := certFor(t, "*.other.example.test", time.Now().Add(-time.Hour), time.Now().Add(400*24*time.Hour), nil)
	if _, err := m.UploadApps(ctx, wrong, wrongKey, ""); err == nil || !strings.Contains(err.Error(), "does not name *."+domain) {
		t.Fatalf("a certificate for another name was taken: %v", err)
	}
	certPEM, keyPEM := certFor(t, "*."+domain, time.Now().Add(-time.Hour), time.Now().Add(400*24*time.Hour), nil)
	info, err := m.UploadApps(ctx, certPEM, keyPEM, "")
	if err != nil || info.Source != SourceApps || strings.Join(info.Hosts, ",") != "*."+domain {
		t.Fatalf("upload: %v %+v", err, info)
	}
	if err := m.AppsReady(domain); err != nil {
		t.Fatalf("AppsReady: %v", err)
	}
	if err := m.AppsReady("elsewhere.test"); err == nil || !strings.Contains(err.Error(), "not *.elsewhere.test") {
		t.Fatalf("AppsReady for another domain: %v", err)
	}
	for name, wantApps := range map[string]bool{
		"wiki." + domain: true, "WIKI." + domain: true,
		"gw.example.test": false, domain: false, "a.b." + domain: false, "wiki." + domain + ".evil": false, "": false,
	} {
		got, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
		if err != nil {
			t.Fatal(err)
		}
		isApps := describe("", got.Leaf, "").Fingerprint == info.Fingerprint
		if isApps != wantApps {
			t.Errorf("handshake for %q got the apps certificate: %v, want %v", name, isApps, wantApps)
		}
	}
	if got, err := m.GetCertificate(nil); err != nil || describe("", got.Leaf, "").Fingerprint != console.Fingerprint {
		t.Fatalf("handshake without a name: %v", err)
	}
	if hosts := m.AppsHosts(); strings.Join(hosts, ",") != "*."+domain {
		t.Fatalf("AppsHosts: %v", hosts)
	}

	// A new process serves the stored certificate, and the console's own
	// slot is untouched by it.
	again := &Manager{Repo: repo, Log: log, Hosts: []string{"gw.example.test"}, AppsDomain: func() string { return domain }}
	if err := again.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if a, ok := again.Apps(); !ok || a.Fingerprint != info.Fingerprint || again.Active().Fingerprint != console.Fingerprint {
		t.Fatalf("reloaded: %+v / %+v", a, again.Active())
	}
	if err := again.ResetApps(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := again.Apps(); ok || again.AppsReady(domain) == nil {
		t.Fatal("reset left an applications certificate")
	}
}

// TestAppsRoutes: the apps certificate has its own upload and removal, the
// status reports it with the domain and whether applications can be served,
// and both are audited without key material.
func TestAppsRoutes(t *testing.T) {
	ctx := context.Background()
	repo, db := newRepo(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{6}, 32), false)
	auditLog := audit.NewLog(db)
	domain := "apps.example.test"
	m := &Manager{Repo: repo, Log: log, Hosts: []string{"gw"}, AppsDomain: func() string { return domain }}
	if err := m.Load(ctx); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&Handler{Manager: m, Mode: "managed", Audit: auditLog, Log: log}).Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	srv := mw.Authenticate(mw.CSRF(mux))
	u := &user.User{Username: "root", DisplayName: "root", Roles: []user.Role{user.RoleAdmin}}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	tok, sess, err := sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID)
	do := func(method, path string, body any) (int, map[string]any, string) {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.RemoteAddr = "203.0.113.9:4321"
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out, rr.Body.String()
	}
	code, out, _ := do("GET", "/api/v1/admin/tls", nil)
	if code != 200 || out["apps_domain"] != domain || out["apps_ready"] != false || out["apps"] != nil || out["apps_problem"] == "" {
		t.Fatalf("status before: %d %v", code, out)
	}
	certPEM, keyPEM := certFor(t, "*."+domain, time.Now().Add(-time.Hour), time.Now().Add(400*24*time.Hour), nil)
	code, out, raw := do("PUT", "/api/v1/admin/tls/apps", map[string]string{"cert_pem": certPEM, "key_pem": keyPEM})
	if code != 200 || out["apps_ready"] != true || out["apps"].(map[string]any)["source"] != SourceApps || strings.Contains(raw, "PRIVATE KEY") {
		t.Fatalf("upload: %d %s", code, raw)
	}
	if out["active"].(map[string]any)["source"] != SourceGenerated {
		t.Fatalf("the console's certificate changed: %v", out["active"])
	}
	if code, out, _ := do("PUT", "/api/v1/admin/tls/apps", map[string]string{"cert_pem": certPEM, "key_pem": "nope"}); code != 400 {
		t.Fatalf("bad key: %d %v", code, out)
	}
	if code, out, _ := do("DELETE", "/api/v1/admin/tls/apps", nil); code != 200 || out["apps_ready"] != false || out["apps"] != nil {
		t.Fatalf("reset: %d %v", code, out)
	}
	events, _, err := auditLog.List(ctx, audit.Filter{ObjectType: "tls_certificate"})
	if err != nil || len(events) != 2 {
		t.Fatalf("audit: %d %v", len(events), err)
	}
	for _, ev := range events {
		if !strings.Contains(string(ev.Details), `"for":"apps"`) || strings.Contains(string(ev.Details), "PRIVATE") {
			t.Fatalf("audit details: %s", ev.Details)
		}
	}
}
