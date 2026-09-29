// SPDX-License-Identifier: Apache-2.0

package recstorage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

// fakeS3 is an in-memory bucket; failPut makes every upload fail.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	failPut bool
	puts    int
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	if f.failPut {
		return nil, errors.New("AccessDenied")
	}
	b, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	if f.objects == nil {
		f.objects = map[string][]byte{}
	}
	f.objects[*in.Bucket+"/"+*in.Key] = b
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[*in.Bucket+"/"+*in.Key]
	if !ok {
		return nil, errors.New("NoSuchKey")
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(b))}, nil
}

func (f *fakeS3) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, *in.Bucket+"/"+*in.Key)
	return &s3.DeleteObjectOutput{}, nil
}

type harness struct {
	db       *store.DB
	repo     *Repo
	sessions *session.Repo
	router   *recording.Router
	fake     *fakeS3
	dir      string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	kek, _ := crypto.NewLocalKEK(bytes.Repeat([]byte{8}, 32))
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	dir := t.TempDir()
	return &harness{db: db, repo: NewRepo(db, ring), sessions: session.NewRepo(db), router: &recording.Router{Local: &recording.LocalStorage{Dir: dir}}, fake: &fakeS3{}, dir: dir}
}

func (h *harness) manager(env *Config) *Manager {
	return &Manager{Repo: h.repo, Router: h.router, Sessions: h.sessions, Env: env, SpoolDir: filepath.Join(h.dir, "spool"),
		Build: func(_ context.Context, o recording.S3Options) (*recording.S3Storage, error) {
			return recording.NewS3StorageWithClient(h.fake, o), nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// TestApplyProbeAndPrecedence: with nothing configured the local directory
// serves; a bucket that refuses uploads is not saved and local stays
// active; a working one is probed (the probe object is removed), sealed,
// active for the next recording and seen again by a fresh manager; Reset
// goes back to the environment's bucket, and without one to local.
func TestApplyProbeAndPrecedence(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	m := h.manager(nil)
	if err := m.Load(ctx); err != nil || m.Source() != SourceLocal || h.router.S3() != nil {
		t.Fatalf("load: %v %s", err, m.Source())
	}
	h.fake.failPut = true
	err := m.Apply(ctx, Config{Bucket: "recs", Auth: AuthKeys, AccessKeyID: "AKIAEXAMPLE1234", SecretAccessKey: "s3cret"}, "")
	if err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "probe failed") || h.router.S3() != nil {
		t.Fatalf("refusing bucket must not be saved: %v", err)
	}
	h.fake.failPut = false
	if err := m.Apply(ctx, Config{Bucket: "recs", Prefix: "/gw/", Auth: AuthKeys, AccessKeyID: "AKIAEXAMPLE1234", SecretAccessKey: "s3cret"}, ""); err != nil {
		t.Fatal(err)
	}
	if m.Source() != SourceConsole || h.router.S3() == nil || len(h.fake.objects) != 0 {
		t.Fatalf("apply: source=%s objects=%d", m.Source(), len(h.fake.objects))
	}
	a := m.Active()
	if a.SecretAccessKey != "" || !a.SecretSet || a.AccessKeyID != "…1234" || a.Prefix != "gw/" {
		t.Fatalf("public view: %+v", a)
	}
	var sealed []byte
	if err := h.db.QueryRowContext(ctx, `SELECT secret_enc FROM recording_storage`).Scan(&sealed); err != nil || bytes.Contains(sealed, []byte("s3cret")) {
		t.Fatalf("secret must be sealed: %v", err)
	}
	w, uri, err := h.router.Create(ctx, "x.cast")
	if err != nil || !strings.HasPrefix(uri, "s3://recs/gw/") {
		t.Fatalf("new recordings go to the bucket: %s %v", uri, err)
	}
	_, _ = io.WriteString(w, "hi")
	_ = w.Close()

	again := h.manager(nil)
	if err := again.Load(ctx); err != nil || again.Source() != SourceConsole {
		t.Fatalf("reload: %v %s", err, again.Source())
	}
	if c, _ := h.repo.Get(ctx); c.SecretAccessKey != "s3cret" {
		t.Fatal("sealed secret must round-trip")
	}
	// Keeping the keys without resending the secret keeps the stored one.
	if err := m.Apply(ctx, Config{Bucket: "recs", Prefix: "gw2", Auth: AuthKeys, AccessKeyID: "AKIAEXAMPLE1234"}, ""); err != nil {
		t.Fatalf("apply without secret: %v", err)
	}

	env := &Config{Bucket: "envbucket", Prefix: "recordings/", Auth: AuthRole}
	withEnv := h.manager(env)
	if err := withEnv.Reset(ctx); err != nil || withEnv.Source() != SourceEnvironment || h.router.S3().Bucket != "envbucket" {
		t.Fatalf("reset to environment: %v %s", err, withEnv.Source())
	}
	if err := m.Reset(ctx); err != nil || m.Source() != SourceLocal || h.router.S3() != nil {
		t.Fatalf("reset to local: %v %s", err, m.Source())
	}
	if _, err := h.router.Open(ctx, uri); err == nil {
		t.Fatal("an S3 recording cannot be opened with no bucket configured")
	}
}

// TestValidate: bucket names, prefixes, endpoints and auth modes.
func TestValidate(t *testing.T) {
	good := Config{Bucket: "my-bucket", Prefix: "", Auth: ""}
	if err := good.Validate(); err != nil || good.Prefix != "recordings/" || good.Auth != AuthRole {
		t.Fatalf("defaults: %+v %v", good, err)
	}
	for _, bad := range []Config{
		{Bucket: "Bad_Bucket"},
		{Bucket: "ok", Prefix: "../x"},
		{Bucket: "ok", Endpoint: "minio:9000"},
		{Bucket: "ok", Auth: AuthKeys, AccessKeyID: "AKIA"},
		{Bucket: "ok", Auth: "magic"},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v must be refused", bad)
		}
	}
}

// TestMoveLocalRecordings: finished local recordings are copied to the
// bucket, their digest checked, their rows repointed and the files removed;
// an unfinished one is left alone; a digest mismatch is not accepted.
func TestMoveLocalRecordings(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	m := h.manager(nil)
	if err := m.Load(ctx); err != nil {
		t.Fatal(err)
	}
	owner := &user.User{Username: "alice", DisplayName: "alice", Roles: []user.Role{user.RoleUser}}
	if err := user.NewRepo(h.db).Create(ctx, owner); err != nil {
		t.Fatal(err)
	}
	tgt := &target.Target{Name: "web-01", Address: "10.0.1.10", OSFamily: target.Linux}
	if err := target.NewRepo(h.db).Create(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	mk := func(name, content string, finish bool, sha string) *session.Recording {
		w, uri, err := h.router.Create(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, content)
		_ = w.Close()
		sess := &session.Session{UserID: owner.ID, TargetID: tgt.ID, Protocol: "ssh", ClientIP: "203.0.113.9"}
		if err := h.sessions.Start(ctx, sess); err != nil {
			t.Fatal(err)
		}
		rec := &session.Recording{SessionID: sess.ID, Format: "asciicast", StorageURI: uri}
		if err := h.sessions.CreateRecording(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if finish {
			if sha == "" {
				sum := sha256.Sum256([]byte(content))
				sha = hex.EncodeToString(sum[:])
			}
			if err := h.sessions.FinishRecording(ctx, rec.ID, int64(len(content)), sha); err != nil {
				t.Fatal(err)
			}
		}
		return rec
	}
	done := mk("a.cast", "recording a", true, "")
	live := mk("b.cast", "recording b", false, "")
	corrupt := mk("c.cast", "recording c", true, "0000000000000000000000000000000000000000000000000000000000000000")
	if err := m.Apply(ctx, Config{Bucket: "recs", Auth: AuthRole}, ""); err != nil {
		t.Fatal(err)
	}
	final := make(chan Move, 1)
	if err := m.StartMove(ctx, func(mv Move) { final <- mv }); err != nil {
		t.Fatal(err)
	}
	if err := m.StartMove(ctx, nil); err != nil && !errors.Is(err, ErrBusy) {
		t.Fatalf("second move: %v", err)
	}
	var mv Move
	select {
	case mv = <-final:
	case <-time.After(5 * time.Second):
		t.Fatal("move did not finish")
	}
	if mv.Running || mv.Moved != 1 || mv.Failed != 1 || mv.Total != 2 {
		t.Fatalf("move state: %+v", mv)
	}
	got, _ := h.sessions.GetRecording(ctx, done.ID)
	if !strings.HasPrefix(got.StorageURI, "s3://recs/recordings/") {
		t.Fatalf("moved row: %s", got.StorageURI)
	}
	if _, err := os.Stat(strings.TrimPrefix(done.StorageURI, "file://")); !os.IsNotExist(err) {
		t.Fatal("local file must be removed after the move")
	}
	rc, err := h.router.Open(ctx, got.StorageURI)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != "recording a" {
		t.Fatalf("moved content: %q", b)
	}
	for _, rec := range []*session.Recording{live, corrupt} {
		got, _ := h.sessions.GetRecording(ctx, rec.ID)
		if !strings.HasPrefix(got.StorageURI, "file://") {
			t.Fatalf("%s must stay local: %s", rec.ID, got.StorageURI)
		}
	}
	counts, _ := h.sessions.CountRecordingsByStore(ctx)
	if counts["local"] != 2 || counts["s3://recs"] != 1 {
		t.Fatalf("counts: %v", counts)
	}
}

// TestRoutes: status carries source and counts, never a secret; test and
// save probe; a user is refused; the audit rows carry no secret.
func TestRoutes(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	m := h.manager(nil)
	if err := m.Load(ctx); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(h.db)
	sessions := auth.NewSessions(h.db, bytes.Repeat([]byte{9}, 32), false)
	auditLog := audit.NewLog(h.db)
	mux := http.NewServeMux()
	(&Handler{Manager: m, Audit: auditLog, Log: log}).Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	srv := mw.Authenticate(mw.CSRF(mux))
	login := func(name string, role user.Role) (*http.Cookie, string) {
		u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{role}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok, sess, err := sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID)
	}
	admin, aCSRF := login("root", user.RoleAdmin)
	plain, pCSRF := login("alice", user.RoleUser)
	do := func(method, path string, body any, cookie *http.Cookie, csrf string) (int, map[string]any, string) {
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
	if code, out, _ := do("GET", "/api/v1/admin/storage", nil, admin, aCSRF); code != 200 || out["source"] != SourceLocal {
		t.Fatalf("status: %d %v", code, out)
	}
	if code, _, _ := do("GET", "/api/v1/admin/storage", nil, plain, pCSRF); code != 403 {
		t.Fatalf("user: %d", code)
	}
	cfg := map[string]any{"bucket": "recs", "auth": "keys", "access_key_id": "AKIAEXAMPLE9999", "secret_access_key": "topsecret"}
	if code, out, _ := do("POST", "/api/v1/admin/storage/test", cfg, admin, aCSRF); code != 200 || out["ok"] != true {
		t.Fatalf("test: %d %v", code, out)
	}
	h.fake.failPut = true
	if code, out, _ := do("PUT", "/api/v1/admin/storage", cfg, admin, aCSRF); code != 400 || !strings.Contains(out["message"].(string), "probe failed") {
		t.Fatalf("failing bucket: %d %v", code, out)
	}
	h.fake.failPut = false
	code, out, raw := do("PUT", "/api/v1/admin/storage", cfg, admin, aCSRF)
	if code != 200 || out["source"] != SourceConsole || strings.Contains(raw, "topsecret") || strings.Contains(raw, "AKIAEXAMPLE9999") {
		t.Fatalf("save: %d %s", code, raw)
	}
	if code, out, _ := do("POST", "/api/v1/admin/storage/move", nil, admin, aCSRF); code != 202 || out["move"].(map[string]any)["running"] != true && out["move"].(map[string]any)["finished_at"] == nil {
		t.Fatalf("move: %d %v", code, out)
	}
	if code, out, _ := do("DELETE", "/api/v1/admin/storage", nil, admin, aCSRF); code != 200 || out["source"] != SourceLocal {
		t.Fatalf("reset: %d %v", code, out)
	}
	events, _, err := auditLog.List(ctx, audit.Filter{ObjectType: "recording_storage"})
	if err != nil || len(events) < 2 {
		t.Fatalf("audit: %d %v", len(events), err)
	}
	for _, ev := range events {
		if strings.Contains(string(ev.Details), "topsecret") || strings.Contains(string(ev.Details), "AKIAEXAMPLE9999") {
			t.Fatalf("audit leaks a secret: %s", ev.Details)
		}
	}
}
