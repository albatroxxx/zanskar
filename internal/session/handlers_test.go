// SPDX-License-Identifier: Apache-2.0

package session

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
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

type env struct {
	srv     http.Handler
	db      *store.DB
	repo    *Repo
	audit   *audit.Log
	storage *recording.LocalStorage
	cookies map[string]*http.Cookie
	csrf    map[string]string
	ids     map[string]string // username -> user id
}

// newEnv wires the session handler behind the real auth middleware with an
// admin, an auditor and a plain user, local recording storage in a temp
// directory, and one target with a session.
func newEnv(t *testing.T) *env {
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
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{6}, 32), false)
	e := &env{db: db, repo: NewRepo(db), audit: audit.NewLog(db), storage: &recording.LocalStorage{Dir: t.TempDir()}, cookies: map[string]*http.Cookie{}, csrf: map[string]string{}, ids: map[string]string{}}
	h := &Handler{Repo: e.repo, Audit: e.audit, Storage: e.storage, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	e.srv = mw.Authenticate(mw.CSRF(mux))
	for name, role := range map[string]user.Role{"root": user.RoleAdmin, "reviewer": user.RoleAuditor, "alice": user.RoleUser} {
		u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{role}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok, sess, err := sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		e.cookies[name] = &http.Cookie{Name: auth.CookieName, Value: tok}
		e.csrf[name], e.ids[name] = sessions.CSRFToken(sess.ID), u.ID
	}
	now := store.TimeArg(time.Now())
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES ('t1', 'web 1', '10.0.0.5', 'linux', ?, ?)`), now, now); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) get(path, who string) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = "203.0.113.9:4321"
	req.AddCookie(e.cookies[who])
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

// record writes a finished recording of the given format for alice on t1,
// with two command markers for the terminal case, and returns its id.
func (e *env) record(t *testing.T, format string) string {
	t.Helper()
	ctx := context.Background()
	var alice string
	if err := e.db.QueryRowContext(ctx, `SELECT id FROM users WHERE username = 'alice'`).Scan(&alice); err != nil {
		t.Fatal(err)
	}
	s := &Session{UserID: alice, TargetID: "t1", Protocol: "ssh", ClientIP: "10.0.0.1"}
	if format == "guac" {
		s.Protocol = "rdp"
	}
	if err := e.repo.Start(ctx, s); err != nil {
		t.Fatal(err)
	}
	var uri string
	var size int64
	var sum string
	if format == "asciicast" {
		cast, u, err := recording.NewAsciicast(ctx, e.storage, s.ID+".cast", recording.Header{Width: 80, Height: 24, Title: "test"})
		if err != nil {
			t.Fatal(err)
		}
		_ = cast.Output([]byte("$ "))
		_ = cast.Marker("ls -la")
		_ = cast.Marker("(hidden input)")
		size, sum, err = cast.Close()
		if err != nil {
			t.Fatal(err)
		}
		uri = u
	} else {
		w, u, err := e.storage.Create(ctx, s.ID+".guac")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte("4.size,1.0,4.1024,3.768;"))
		_ = w.Close()
		uri, size, sum = u, 24, "deadbeef"
	}
	rec := &Recording{SessionID: s.ID, Format: format, StorageURI: uri}
	if err := e.repo.CreateRecording(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := e.repo.FinishRecording(ctx, rec.ID, size, sum); err != nil {
		t.Fatal(err)
	}
	if err := e.repo.End(ctx, s.ID, EndUserExit); err != nil {
		t.Fatal(err)
	}
	return rec.ID
}

// TestRecordingDownloads covers the evidence downloads: reviewers (admin and
// auditor) get the raw recording and, for terminal sessions, a plain-text
// command transcript, each as a named attachment and each recorded as a
// view and an audit event naming the downloader; a plain user is refused;
// a desktop recording has no transcript.
func TestRecordingDownloads(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	term := e.record(t, "asciicast")
	desk := e.record(t, "guac")

	if rr, out := e.get("/api/v1/recordings/"+term+"/download", "alice"); rr.Code != 403 || out["code"] != "forbidden" {
		t.Fatalf("user must not download: %d %v", rr.Code, out)
	}
	rr, _ := e.get("/api/v1/recordings/"+term+"/download", "reviewer")
	if rr.Code != 200 {
		t.Fatalf("auditor download: %d %s", rr.Code, rr.Body.String())
	}
	cd := rr.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, `attachment; filename="alice-web_1-`) || !strings.HasSuffix(cd, `.cast"`) {
		t.Fatalf("attachment name: %q", cd)
	}
	if !strings.Contains(rr.Body.String(), `"m", "ls -la"`) && !strings.Contains(rr.Body.String(), `"m","ls -la"`) {
		t.Fatalf("raw download must be the asciicast: %s", rr.Body.String())
	}

	rr, _ = e.get("/api/v1/recordings/"+term+"/transcript", "root")
	if rr.Code != 200 || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("admin transcript: %d %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"# alice on web 1 (SSH)", "00:00:00  ls -la", "00:00:00  (hidden input)", "sha256 "} {
		if !strings.Contains(body, want) {
			t.Fatalf("transcript missing %q:\n%s", want, body)
		}
	}
	if !strings.HasSuffix(rr.Header().Get("Content-Disposition"), `-commands.txt"`) {
		t.Fatalf("transcript attachment name: %q", rr.Header().Get("Content-Disposition"))
	}

	if rr, out := e.get("/api/v1/recordings/"+desk+"/transcript", "reviewer"); rr.Code != 409 || out["code"] != "not_a_terminal_recording" {
		t.Fatalf("desktop transcript: %d %v", rr.Code, out)
	}
	if rr, _ := e.get("/api/v1/recordings/"+desk+"/download", "reviewer"); rr.Code != 200 || !strings.HasSuffix(rr.Header().Get("Content-Disposition"), `.guac"`) {
		t.Fatalf("desktop download: %d %q", rr.Code, rr.Header().Get("Content-Disposition"))
	}

	// Every successful download is a view and an audit event with its kind.
	events, _, err := e.audit.List(ctx, audit.Filter{Action: "recording.download"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("want 3 download events, got %d", len(events))
	}
	kinds := map[string]int{}
	for _, ev := range events {
		var d map[string]any
		_ = json.Unmarshal(ev.Details, &d)
		kinds[d["kind"].(string)]++
		if ev.ActorUserID == "" {
			t.Fatalf("download event must name the downloader: %+v", ev)
		}
	}
	if kinds["raw"] != 2 || kinds["transcript"] != 1 {
		t.Fatalf("event kinds: %v", kinds)
	}
	var views int
	if err := e.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recording_views`).Scan(&views); err != nil || views != 3 {
		t.Fatalf("recording_views: %d %v", views, err)
	}
}
