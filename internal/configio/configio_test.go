// SPDX-License-Identifier: Apache-2.0

package configio

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
	"github.com/albatroxxx/zanskar/internal/user/adminapi"
)

// gw is one gateway: the real handlers behind the real middleware, an
// administrator signed in, and a credential named "linux-key".
type gw struct {
	db     *store.DB
	srv    http.Handler
	cookie *http.Cookie
	csrf   string
	audit  *audit.Log
	userCk *http.Cookie
}

func newGW(t *testing.T) *gw {
	t.Helper()
	ctx := context.Background()
	db := storetest.Open(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	kek, _ := crypto.NewLocalKEK(bytes.Repeat([]byte{9}, 32))
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{4}, 32), false)
	vault := credential.NewVault(db, ring)
	al := audit.NewLog(db)
	mux := http.NewServeMux()
	ci := &Handler{Audit: al, Log: log}
	for _, h := range []interface{ Register(*http.ServeMux) }{
		&adminapi.AdminHandler{Users: users, Audit: al, Log: log},
		&group.AdminHandler{Groups: group.NewRepo(db), Audit: al, Log: log},
		&credential.AdminHandler{Vault: vault, Audit: al, Log: log},
		&target.AdminHandler{Repo: target.NewRepo(db), Prober: &target.Prober{}, Audit: al, Log: log},
		&policy.AdminHandler{Repo: policy.NewRepo(db), Users: users, Audit: al, Log: log},
		ci,
	} {
		h.Register(mux)
	}
	// No autoscaling here: its list is empty.
	mux.HandleFunc("GET /api/v1/autoscaling-groups", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"items":[]}`) })
	ci.UseMux(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	g := &gw{db: db, srv: mw.Authenticate(mw.CSRF(mux)), audit: al}
	for name, role := range map[string]user.Role{"root": user.RoleAdmin, "ann": user.RoleUser} {
		u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{role}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok, sess, err := sessions.Create(ctx, u.ID, "127.0.0.1", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		if name == "root" {
			g.cookie, g.csrf = &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID)
		} else {
			g.userCk = &http.Cookie{Name: auth.CookieName, Value: tok}
		}
	}
	if err := vault.Create(ctx, &credential.Credential{Name: "linux-key", Type: credential.TypePassword, Mode: credential.ModeVaulted, Username: "ubuntu"},
		&credential.Secret{Password: "s3cret-pw"}, ""); err != nil {
		t.Fatal(err)
	}
	return g
}

func (g *gw) do(t *testing.T, method, path string, body []byte) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", g.csrf)
	req.AddCookie(g.cookie)
	rr := httptest.NewRecorder()
	g.srv.ServeHTTP(rr, req)
	return rr.Code, rr.Body.Bytes()
}

func (g *gw) json(t *testing.T, method, path string, v any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(v)
	code, out := g.do(t, method, path, b)
	if code < 200 || code > 299 {
		t.Fatalf("%s %s: %d %s", method, path, code, out)
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	return m
}

// 2026-11-03, idea 10 (ADR 0043): a gateway's configuration, exported as
// YAML by name and imported into another, rebuilds it through the API; a
// second import changes nothing; secrets never travel.
func TestExportImportRoundTrip(t *testing.T) {
	a := newGW(t)
	var credID string
	if err := a.db.QueryRowContext(context.Background(), `SELECT id FROM credentials WHERE name = 'linux-key'`).Scan(&credID); err != nil {
		t.Fatal(err)
	}
	var annID string
	_ = a.db.QueryRowContext(context.Background(), `SELECT id FROM users WHERE username = 'ann'`).Scan(&annID)
	grp := a.json(t, "POST", "/api/v1/groups", map[string]any{"name": "ops", "description": "on call", "user_ids": []string{annID}})
	web := a.json(t, "POST", "/api/v1/targets", map[string]any{"name": "web-1", "address": "10.0.0.5", "os_family": "linux",
		"tags": map[string]string{"env": "prod"}, "credentials": map[string]string{"ssh": credID}})
	a.json(t, "POST", "/api/v1/access-policies", map[string]any{"name": "ops-web", "subjects": []map[string]string{{"kind": "group", "id": grp["id"].(string)}},
		"grants": []map[string]any{{"kind": "host", "targets": []map[string]any{{"id": web["id"], "protocols": []string{"ssh"}}}, "require_watcher": true}}})

	code, file := a.do(t, "GET", "/api/v1/admin/config/export", nil)
	if code != 200 {
		t.Fatalf("export: %d %s", code, file)
	}
	text := string(file)
	for _, want := range []string{"zanskar: 1", "name: ops", "- ann", "name: web-1", "ssh: linux-key", "env: prod", "name: ops-web", "group: ops", "name: web-1", "require_watcher: true"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the export lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "s3cret") || strings.Contains(text, credID) || strings.Contains(text, web["id"].(string)) {
		t.Fatalf("the export carries a secret or an id:\n%s", text)
	}

	b := newGW(t)
	// The plan first: everything is new, nothing changed yet.
	code, out := b.do(t, "POST", "/api/v1/admin/config/import", file)
	if code != 200 || !strings.Contains(string(out), `"applied":false`) || strings.Count(string(out), `"action":"create"`) != 3 {
		t.Fatalf("plan: %d %s", code, out)
	}
	if n := count(t, b.db, "targets"); n != 0 {
		t.Fatalf("a plan changed something: %d targets", n)
	}
	code, out = b.do(t, "POST", "/api/v1/admin/config/import?apply=true", file)
	if code != 200 || strings.Count(string(out), `"applied":true`) != 4 {
		t.Fatalf("apply: %d %s", code, out)
	}
	// B now exports what A did.
	_, again := b.do(t, "GET", "/api/v1/admin/config/export", nil)
	if strip(string(again)) != strip(text) {
		t.Fatalf("the round trip differs:\n--- A\n%s\n--- B\n%s", text, again)
	}
	// A second import changes nothing.
	_, out = b.do(t, "POST", "/api/v1/admin/config/import?apply=true", file)
	if strings.Contains(string(out), `"action":"create"`) || strings.Contains(string(out), `"action":"update"`) {
		t.Fatalf("a second import changed things: %s", out)
	}
	// Every change went through the API, so each is in the log as usual.
	if evs, _, _ := b.audit.List(context.Background(), audit.Filter{Action: audit.TargetCreate}); len(evs) != 1 {
		t.Fatalf("target.create events: %d", len(evs))
	}
	if evs, _, _ := b.audit.List(context.Background(), audit.Filter{Action: audit.ConfigImport}); len(evs) != 2 {
		t.Fatalf("config.import events: %d", len(evs))
	}
}

// A file naming what this gateway lacks is refused whole, before anything
// changes; the API's own rules (a forbidden address) refuse the rest.
func TestImportRefusals(t *testing.T) {
	g := newGW(t)
	missing := []byte("zanskar: 1\ntargets:\n  - name: db-1\n    address: 10.0.0.9\n    os_family: linux\n    credentials: {ssh: nowhere}\npolicies:\n  - name: p\n    enabled: true\n    subjects: [{group: ghosts}]\n")
	code, out := g.do(t, "POST", "/api/v1/admin/config/import?apply=true", missing)
	if code != 422 || !strings.Contains(string(out), `credential \"nowhere\" does not exist`) || !strings.Contains(string(out), `group \"ghosts\" does not exist`) {
		t.Fatalf("missing names: %d %s", code, out)
	}
	if count(t, g.db, "targets") != 0 {
		t.Fatal("a refused import created a target")
	}
	forbidden := []byte("zanskar: 1\ntargets:\n  - name: meta\n    address: 169.254.169.254\n    os_family: linux\n")
	code, out = g.do(t, "POST", "/api/v1/admin/config/import?apply=true", forbidden)
	if code != 409 || !strings.Contains(string(out), `"error"`) || count(t, g.db, "targets") != 0 {
		t.Fatalf("a forbidden address went in: %d %s", code, out)
	}
	for _, bad := range []string{"zanskar: 2\n", "zanskar: 1\nsurprise: true\n", "not: [yaml"} {
		if code, _ := g.do(t, "POST", "/api/v1/admin/config/import", []byte(bad)); code != 400 {
			t.Fatalf("%q: %d", bad, code)
		}
	}
	// Administrators only.
	req := httptest.NewRequest("GET", "/api/v1/admin/config/export", nil)
	req.AddCookie(g.userCk)
	rr := httptest.NewRecorder()
	g.srv.ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("a user exported the configuration: %d", rr.Code)
	}
}

func count(t *testing.T, db *store.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil { // #nosec G202 -- a test's own table names
		t.Fatal(err)
	}
	return n
}

// strip drops the export's time, which two exports never share.
func strip(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(l, "exported_at:") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
