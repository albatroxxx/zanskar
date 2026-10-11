// SPDX-License-Identifier: Apache-2.0

package server

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

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

type probeRoutes struct{ log *slog.Logger }

func (p probeRoutes) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/probe/bad", func(w http.ResponseWriter, r *http.Request) {
		httpx.BadRequest(w, r, "nope")
	})
	mux.HandleFunc("GET /api/v1/probe/boom", func(w http.ResponseWriter, r *http.Request) {
		httpx.Internal(w, r, p.log, errors.New("database is down\nforged line"))
	})
	mux.HandleFunc("GET /api/v1/probe/panic", func(http.ResponseWriter, *http.Request) {
		panic("probe")
	})
	mux.Handle("GET /api/v1/probe/private", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
}

// TestEveryErrorCarriesTheRequestID: the spec promises a request_id in every
// error body, to quote in a bug report, but only the server's own 404 and
// panic replies had one (M22). A handler's error, the auth middleware's
// refusal, a 500 and a recovered panic all carry the response's
// X-Request-Id now, and the 500's log line carries it too, beside the
// route rather than the caller's path.
func TestEveryErrorCarriesTheRequestID(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	mw := &auth.Middleware{Sessions: auth.NewSessions(db, bytes.Repeat([]byte{7}, 32), false), Users: user.NewRepo(db), Log: log}
	s := New(&config.Config{ListenAddr: "127.0.0.1:0"}, db, log, Deps{AuthMiddleware: mw, Handlers: []Registrar{probeRoutes{log: log}}})

	for path, want := range map[string]struct {
		status int
		code   string
	}{
		"/api/v1/probe/bad":     {http.StatusBadRequest, "bad_request"},
		"/api/v1/probe/boom":    {http.StatusInternalServerError, "internal"},
		"/api/v1/probe/panic":   {http.StatusInternalServerError, "internal"},
		"/api/v1/probe/private": {http.StatusUnauthorized, "unauthenticated"},
		"/api/v1/nope":          {http.StatusNotFound, "not_found"},
	} {
		logs.Reset()
		rr := httptest.NewRecorder()
		s.http.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: %v: %s", path, err, rr.Body)
		}
		id := rr.Header().Get("X-Request-Id")
		if rr.Code != want.status || body["code"] != want.code || id == "" || body["request_id"] != id {
			t.Errorf("%s: got %d %v with X-Request-Id %q, want %d %s carrying that id", path, rr.Code, body, id, want.status, want.code)
		}
		if want.status == http.StatusInternalServerError && !strings.Contains(logs.String(), "request_id="+id) {
			t.Errorf("%s: the log does not carry the request id:\n%s", path, logs.String())
		}
		if path == "/api/v1/probe/boom" {
			if !strings.Contains(logs.String(), `route="GET /api/v1/probe/boom"`) || strings.Contains(logs.String(), "\nforged line") {
				t.Errorf("%s: the log line should name the route and keep the error on one line:\n%s", path, logs.String())
			}
		}
	}
}

// TestVersionNeedsASignedInCaller: /api/v1/version told anyone who could
// reach the gateway which release it runs (L16), which is what a scanner
// matches against advisories. It answers a signed-in caller now, such as the
// console's command line; the sign-in page never showed it.
func TestVersionNeedsASignedInCaller(t *testing.T) {
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
	users, sessions := user.NewRepo(db), auth.NewSessions(db, bytes.Repeat([]byte{7}, 32), false)
	s := New(&config.Config{ListenAddr: "127.0.0.1:0"}, db, log, Deps{AuthMiddleware: &auth.Middleware{Sessions: sessions, Users: users, Log: log}})

	rr := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/version", nil))
	if rr.Code != http.StatusUnauthorized || strings.Contains(rr.Body.String(), "version") {
		t.Fatalf("anonymous: %d %s, want 401 without the version", rr.Code, rr.Body)
	}

	u := &user.User{Username: "alice", DisplayName: "Alice", Roles: []user.Role{user.RoleUser}}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	tok, _, err := sessions.Create(ctx, u.ID, "192.0.2.1", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: tok})
	rr = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rr, req)
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); rr.Code != http.StatusOK || err != nil || body["version"] == "" {
		t.Fatalf("signed in: %d %s", rr.Code, rr.Body)
	}
}
