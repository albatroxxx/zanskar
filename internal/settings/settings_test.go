// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/user"
	"github.com/albatroxxx/zanskar/internal/version"
)

func newDB(t *testing.T) *store.DB {
	return storetest.Open(t)
}

// TestPrecedenceAndSubscribe: default, then environment, then console; a
// set tells subscribers at once; a reset falls back and tells them again;
// a fresh service sees what was stored.
func TestPrecedenceAndSubscribe(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	svc := NewService(NewRepo(db), map[string]string{KeyRequireMFA: "false"}, nil)
	if err := svc.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if v, _ := svc.Get(KeyLogLevel); v.Value != "info" || v.Source != SourceDefault {
		t.Fatalf("default: %+v", v)
	}
	if v, _ := svc.Get(KeyRequireMFA); v.Value != "false" || v.Source != SourceEnvironment || svc.Bool(KeyRequireMFA) {
		t.Fatalf("environment: %+v", v)
	}
	admin := &user.User{Username: "root", DisplayName: "root", Roles: []user.Role{user.RoleAdmin}}
	if err := user.NewRepo(db).Create(ctx, admin); err != nil {
		t.Fatal(err)
	}
	var seen []string
	svc.Subscribe(KeyRequireMFA, func(v string) { seen = append(seen, v) })
	if v, err := svc.Set(ctx, KeyRequireMFA, "yes", admin.ID); err != nil || v.Value != "true" || v.Source != SourceConsole || v.UpdatedBy != admin.ID {
		t.Fatalf("set: %+v %v", v, err)
	}
	if !svc.Bool(KeyRequireMFA) || len(seen) != 1 || seen[0] != "true" {
		t.Fatalf("subscriber after set: %v bool=%v", seen, svc.Bool(KeyRequireMFA))
	}
	again := NewService(NewRepo(db), map[string]string{KeyRequireMFA: "false"}, nil)
	if err := again.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if v, _ := again.Get(KeyRequireMFA); v.Value != "true" || v.Source != SourceConsole {
		t.Fatalf("reload: %+v", v)
	}
	if v, err := svc.Reset(ctx, KeyRequireMFA); err != nil || v.Value != "false" || v.Source != SourceEnvironment {
		t.Fatalf("reset: %+v %v", v, err)
	}
	if len(seen) != 2 || seen[1] != "false" {
		t.Fatalf("subscriber after reset: %v", seen)
	}
	if _, err := svc.Set(ctx, "no.such", "x", ""); err == nil {
		t.Fatal("unknown key must be refused")
	}
	if len(svc.All()) != len(Definitions) {
		t.Fatalf("All must cover every definition")
	}
	// A rule beside Validate: what the rest of the configuration forbids.
	svc.Check(KeyAppsDomain, func(v string) error {
		if v == "example.com" {
			return errors.New("holds the console's own host")
		}
		return nil
	})
	if _, err := svc.Set(ctx, KeyAppsDomain, "example.com", admin.ID); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "apps.domain holds the console's own host") {
		t.Fatalf("checked value: %v", err)
	}
	if v, err := svc.Set(ctx, KeyAppsDomain, "apps.example.com", admin.ID); err != nil || v.Value != "apps.example.com" {
		t.Fatalf("allowed value: %+v %v", v, err)
	}
}

func TestValidateTypes(t *testing.T) {
	cases := []struct {
		key, in, want string
		ok            bool
	}{
		{KeyRequireMFA, " TRUE ", "true", true},
		{KeyRequireMFA, "0", "false", true},
		{KeyRequireMFA, "maybe", "", false},
		{KeyLogLevel, "Warn", "warn", true},
		{KeyLogLevel, "verbose", "", false},
		{KeyGuacdAddr, "127.0.0.1:4822", "127.0.0.1:4822", true},
		{KeyGuacdAddr, "", "", true},
		{KeyGuacdAddr, "guacd", "", false},
		{KeyGuacdAddr, "guacd:99999", "", false},
		{KeyLoginBanner, "  a\r\nb  ", "a\nb", true},
		{KeyLoginBanner, strings.Repeat("x", MaxLoginBanner+1), "", false},
		// The relay image lands in a docker run argument vector: an image
		// reference and nothing that could read as another argument.
		{KeyDBProxyImage, " ghcr.io/albatroxxx/zanskar:1.2.0-rc.1 ", "ghcr.io/albatroxxx/zanskar:1.2.0-rc.1", true},
		{KeyDBProxyImage, "zanskar:local", "zanskar:local", true},
		{KeyDBProxyImage, "zanskar", "zanskar", true},
		{KeyDBProxyImage, "localhost:5000/zanskar:dev", "localhost:5000/zanskar:dev", true},
		{KeyDBProxyImage, "registry.example.com:443/mirror/albatroxxx/zanskar_relay__x:1.3.0", "registry.example.com:443/mirror/albatroxxx/zanskar_relay__x:1.3.0", true},
		{KeyDBProxyImage, "ghcr.io/albatroxxx/zanskar@sha256:" + strings.Repeat("ab", 32), "ghcr.io/albatroxxx/zanskar@sha256:" + strings.Repeat("ab", 32), true},
		{KeyDBProxyImage, "ghcr.io/albatroxxx/zanskar:1.3.0@sha256:" + strings.Repeat("0f", 32), "ghcr.io/albatroxxx/zanskar:1.3.0@sha256:" + strings.Repeat("0f", 32), true},
		{KeyDBProxyImage, "--privileged", "", false},
		{KeyDBProxyImage, "-v=/:/host", "", false},
		{KeyDBProxyImage, "zanskar:local --privileged", "", false},
		{KeyDBProxyImage, "zanskar:local\n--privileged", "", false},
		{KeyDBProxyImage, "zanskar:local\x00", "", false},
		{KeyDBProxyImage, "", "", false},
		{KeyDBProxyImage, "ghcr.io/Albatroxxx/zanskar:1.3.0", "", false},
		{KeyDBProxyImage, "ghcr.io/albatroxxx/zanskar:-1", "", false},
		{KeyDBProxyImage, "ghcr.io/albatroxxx/zanskar:" + strings.Repeat("t", 129), "", false},
		{KeyDBProxyImage, "ghcr.io/albatroxxx/zanskar@sha256:" + strings.Repeat("ab", 31), "", false},
		{KeyDBProxyImage, "ghcr.io/albatroxxx/zanskar@sha256:" + strings.Repeat("AB", 32), "", false},
		{KeyDBProxyImage, "ghcr.io/albatroxxx/zanskar@md5:" + strings.Repeat("ab", 16), "", false},
		{KeyDBProxyImage, "https://ghcr.io/albatroxxx/zanskar", "", false},
		{KeyDBProxyImage, "ghcr.io/" + strings.Repeat("a", 250) + "/zanskar", "", false},
		{KeyDBProxyImage, strings.Repeat("a", 5000), "", false},
		// The apps domain is matched against request hosts and named in
		// certificates: one plain domain, lowercased, nothing else.
		{KeyAppsDomain, " Apps.Example.com. ", "apps.example.com", true},
		{KeyAppsDomain, "", "", true},
		{KeyAppsDomain, "apps", "", false},
		{KeyAppsDomain, "*.apps.example.com", "", false},
		{KeyAppsDomain, "https://apps.example.com", "", false},
		{KeyAppsDomain, "apps.example.com:8443", "", false},
		{KeyAppsDomain, "apps_x.example.com", "", false},
		{KeyAppsDomain, "-apps.example.com", "", false},
	}
	for _, c := range cases {
		d, _ := Lookup(c.key)
		got, err := Validate(d, c.in)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("Validate(%s, %q) = %q, %v; want %q ok=%v", c.key, c.in, got, err, c.want, c.ok)
		}
	}
}

// TestDefaultDBProxyImageValidates: the relay image the gateway uses when no
// one has set one, its own image at its own version, is itself a reference
// the setting accepts, for a release, a candidate and a development build.
func TestDefaultDBProxyImageValidates(t *testing.T) {
	saved := version.Version
	t.Cleanup(func() { version.Version = saved })
	d, _ := Lookup(KeyDBProxyImage)
	// goreleaser's release and snapshot versions, and the Makefile's
	// `git describe --tags --always --dirty` with and without a tag.
	for _, v := range []string{"", "dev", "1.3.0", "1.2.0-rc.1", "1.3.1-snapshot", "v1.3.0-5-gd867b8c-dirty", "d867b8c"} {
		version.Version = v
		img := DefaultDBProxyImage()
		if got, err := Validate(d, img); err != nil || got != img {
			t.Errorf("version %q: default %q refused: %v", v, img, err)
		}
	}
}

// TestLoadSkipsInvalidStoredValue: a value stored before its check existed
// (a relay image that would read as a docker run flag, say) is not used once
// the gateway starts: the environment value, else the default, applies until
// an administrator sets it again. The other stored values still load.
func TestLoadSkipsInvalidStoredValue(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	repo := NewRepo(db)
	if _, err := repo.Set(ctx, KeyDBProxyImage, "--privileged", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Set(ctx, KeyLogLevel, "debug", ""); err != nil {
		t.Fatal(err)
	}
	svc := NewService(repo, nil, nil)
	var logged bytes.Buffer
	svc.Logger = slog.New(slog.NewTextHandler(&logged, nil))
	if err := svc.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if v, _ := svc.Get(KeyDBProxyImage); v.Value != DefaultDBProxyImage() || v.Source != SourceDefault {
		t.Fatalf("a stored relay image that is not an image reference is used: %+v", v)
	}
	if !strings.Contains(logged.String(), "stored setting ignored") || !strings.Contains(logged.String(), KeyDBProxyImage) {
		t.Fatalf("the dropped value is not named at start: %q", logged.String())
	}
	if v, _ := svc.Get(KeyLogLevel); v.Value != "debug" || v.Source != SourceConsole {
		t.Fatalf("a valid stored value was dropped: %+v", v)
	}
	withEnv := NewService(repo, map[string]string{KeyDBProxyImage: "mirror.example.com/zanskar:1.3.0"}, nil)
	if err := withEnv.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if v, _ := withEnv.Get(KeyDBProxyImage); v.Value != "mirror.example.com/zanskar:1.3.0" || v.Source != SourceEnvironment {
		t.Fatalf("the environment value must apply in its place: %+v", v)
	}
}

type env struct {
	srv   http.Handler
	svc   *Service
	audit *audit.Log
	admin *http.Cookie
	aCSRF string
	plain *http.Cookie
	pCSRF string
	// sessions and adminSess let a test prove the administrator's
	// authenticator, which the credential-routing settings ask for.
	sessions  *auth.Sessions
	adminSess string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	db := newDB(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{7}, 32), false)
	boot := []Boot{{Key: "listen_addr", Title: "Listen address", EnvVar: "ZANSKAR_LISTEN_ADDR", Value: "127.0.0.1:8443"}}
	e := &env{svc: NewService(NewRepo(db), map[string]string{KeyLogLevel: "warn"}, boot), audit: audit.NewLog(db)}
	if err := e.svc.Load(ctx); err != nil {
		t.Fatal(err)
	}
	h := &Handler{Service: e.svc, Audit: e.audit, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	e.srv = mw.Authenticate(mw.CSRF(mux))
	e.sessions = sessions
	login := func(name string, role user.Role) (*http.Cookie, string, string) {
		u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{role}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok, sess, err := sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID), sess.ID
	}
	e.admin, e.aCSRF, e.adminSess = login("root", user.RoleAdmin)
	e.plain, e.pCSRF, _ = login("alice", user.RoleUser)
	return e
}

// proved marks the administrator's session as having proved an authenticator
// code just now, which the credential-routing settings ask for.
func (e *env) proved(t *testing.T) {
	t.Helper()
	if err := e.sessions.MarkMFAProved(context.Background(), e.adminSess); err != nil {
		t.Fatal(err)
	}
}

func (e *env) do(method, path string, body any, cookie *http.Cookie, csrf string) (int, map[string]any) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	req.RemoteAddr = "203.0.113.9:4321"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

// TestRoutes covers the generic routes: the listing carries both sections
// with sources; a PUT applies live (a subscriber sees it) and is audited
// with before and after; a DELETE resets to the environment value; a boot
// key is refused with the reason; a user is refused; the login-banner alias
// and the public read still work.
func TestRoutes(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	code, out := e.do("GET", "/api/v1/admin/settings", nil, e.admin, e.aCSRF)
	if code != 200 {
		t.Fatalf("list: %d %v", code, out)
	}
	runtime, _ := out["runtime"].([]any)
	boot, _ := out["boot"].([]any)
	if len(runtime) != len(Definitions) || len(boot) != 1 {
		t.Fatalf("listing shape: %d runtime, %d boot", len(runtime), len(boot))
	}
	var level map[string]any
	for _, it := range runtime {
		m := it.(map[string]any)
		if m["key"] == KeyLogLevel {
			level = m
		}
	}
	if level["value"] != "warn" || level["source"] != SourceEnvironment || level["type"] != string(TypeEnum) {
		t.Fatalf("log level entry: %v", level)
	}

	var applied []string
	e.svc.Subscribe(KeyLogLevel, func(v string) { applied = append(applied, v) })
	if code, out := e.do("PUT", "/api/v1/admin/settings/"+KeyLogLevel, map[string]string{"value": "debug"}, e.plain, e.pCSRF); code != 403 {
		t.Fatalf("user must not set: %d %v", code, out)
	}
	code, out = e.do("PUT", "/api/v1/admin/settings/"+KeyLogLevel, map[string]string{"value": "debug"}, e.admin, e.aCSRF)
	if code != 200 || out["value"] != "debug" || out["source"] != SourceConsole || len(applied) != 1 || applied[0] != "debug" {
		t.Fatalf("set: %d %v applied=%v", code, out, applied)
	}
	if code, out := e.do("PUT", "/api/v1/admin/settings/"+KeyLogLevel, map[string]string{"value": "loud"}, e.admin, e.aCSRF); code != 400 {
		t.Fatalf("bad enum: %d %v", code, out)
	}
	if code, out := e.do("PUT", "/api/v1/admin/settings/listen_addr", map[string]string{"value": "0.0.0.0:443"}, e.admin, e.aCSRF); code != 409 || out["code"] != "boot_setting" {
		t.Fatalf("boot key: %d %v", code, out)
	}
	if code, out := e.do("PUT", "/api/v1/admin/settings/nope", map[string]string{"value": "x"}, e.admin, e.aCSRF); code != 404 {
		t.Fatalf("unknown key: %d %v", code, out)
	}
	// The relay image goes into a docker run argument vector: a value that
	// would read as one of its flags is refused, and saying why. The setting
	// asks for a fresh authenticator first (risk 7); the step-up itself is
	// covered in stepup_test.go.
	e.proved(t)
	for _, bad := range []string{"--privileged", "zanskar:local --privileged", "-v=/:/host"} {
		code, out := e.do("PUT", "/api/v1/admin/settings/"+KeyDBProxyImage, map[string]string{"value": bad}, e.admin, e.aCSRF)
		if msg, _ := out["message"].(string); code != 400 || !strings.Contains(msg, "image reference") {
			t.Fatalf("relay image %q: %d %v, want 400 naming an image reference", bad, code, out)
		}
	}
	if v, _ := e.svc.Get(KeyDBProxyImage); v.Source != SourceDefault {
		t.Fatalf("a refused relay image was stored: %+v", v)
	}
	pinned := "ghcr.io/albatroxxx/zanskar:1.3.0@sha256:" + strings.Repeat("0f", 32)
	if code, out := e.do("PUT", "/api/v1/admin/settings/"+KeyDBProxyImage, map[string]string{"value": pinned}, e.admin, e.aCSRF); code != 200 || out["value"] != pinned {
		t.Fatalf("a pinned relay image: %d %v", code, out)
	}
	if code, out := e.do("DELETE", "/api/v1/admin/settings/"+KeyDBProxyImage, nil, e.admin, e.aCSRF); code != 200 || out["source"] != SourceDefault {
		t.Fatalf("relay image reset: %d %v", code, out)
	}
	code, out = e.do("DELETE", "/api/v1/admin/settings/"+KeyLogLevel, nil, e.admin, e.aCSRF)
	if code != 200 || out["value"] != "warn" || out["source"] != SourceEnvironment || len(applied) != 2 || applied[1] != "warn" {
		t.Fatalf("reset: %d %v applied=%v", code, out, applied)
	}

	// Banner alias and the public read.
	if code, out := e.do("PUT", "/api/v1/admin/settings/login-banner", map[string]string{"value": "Property of Example Ltd.\r\nUse is monitored."}, e.admin, e.aCSRF); code != 200 || out["value"] != "Property of Example Ltd.\nUse is monitored." {
		t.Fatalf("banner alias set: %d %v", code, out)
	}
	if code, out := e.do("GET", "/api/v1/admin/settings/login-banner", nil, e.admin, e.aCSRF); code != 200 || out["source"] != SourceConsole {
		t.Fatalf("banner alias get: %d %v", code, out)
	}
	if code, out := e.do("GET", "/api/v1/system/banner", nil, nil, ""); code != 200 || out["text"] != "Property of Example Ltd.\nUse is monitored." || out["updated_by"] != nil {
		t.Fatalf("public banner: %d %v", code, out)
	}

	// Refused values leave no audit row; the pinned relay image and its
	// reset do.
	events, _, err := e.audit.List(ctx, audit.Filter{ObjectType: "setting"})
	if err != nil || len(events) != 5 {
		t.Fatalf("audit: %d %v", len(events), err)
	}
	actions := map[string]int{}
	for _, ev := range events {
		actions[ev.Action]++
	}
	if actions["settings.update"] != 3 || actions["settings.reset"] != 2 {
		t.Fatalf("audit actions: %v", actions)
	}
}

// TestEnvValuesReportsWhatItCannotUse: an environment value that failed
// validation was dropped without a word (B13): ZANSKAR_GUACD_ADDR=guacd, no
// port, left desktops switched off and nothing said why. It is now an error
// naming the variable, which serve refuses to start on.
func TestEnvValuesReportsWhatItCannotUse(t *testing.T) {
	t.Setenv("ZANSKAR_GUACD_ADDR", "guacd")
	t.Setenv("ZANSKAR_LOG_LEVEL", "info")
	vals, errs := EnvValues()
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "ZANSKAR_GUACD_ADDR") {
		t.Fatalf("errors %v, want one naming ZANSKAR_GUACD_ADDR", errs)
	}
	if _, ok := vals[KeyGuacdAddr]; ok {
		t.Fatal("the bad value must not be used")
	}
	if vals[KeyLogLevel] != "info" {
		t.Fatalf("the good values still come through: %v", vals)
	}
}
