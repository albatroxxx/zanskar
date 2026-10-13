// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestRecorderSurvivesCancelledRequest: net/http cancels r.Context() when the
// client hangs up. The audit row must still land (H7).
func TestRecorderSurvivesCancelledRequest(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("DELETE", "/api/v1/things/1", nil).WithContext(ctx)
	req.RemoteAddr = "203.0.113.9:4000"
	if req.Context().Err() == nil {
		t.Fatal("test setup: request context should already be cancelled")
	}

	rc := Recorder{Audit: e.audit, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rc.Record(req, ActorFor(req).Event("thing.delete", "thing", "1", audit.Success, map[string]string{"why": "test"}))

	events, _, err := e.audit.List(context.Background(), audit.Filter{Action: "thing.delete"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 audit row despite the cancelled request, got %d", len(events))
	}
	if events[0].ActorIP != "203.0.113.9" || events[0].ObjectID != "1" || !bytes.Contains(events[0].Details, []byte(`"why":"test"`)) {
		t.Fatalf("event not stored as given: %+v", events[0])
	}
}

// TestRecorderNilAuditIsNoop: handlers built without an audit log (tests,
// tooling) must neither panic nor log, even with no logger either.
func TestRecorderNilAuditIsNoop(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/things", nil)
	Recorder{}.Record(req, ActorFor(req).Event("thing.create", "thing", "", audit.Success, nil))
}

// TestRecorderLogsFailureWithRoute: when the insert fails the log line names
// the action and the matched route, and nothing from the event's details.
func TestRecorderLogsFailureWithRoute(t *testing.T) {
	db, err := store.Open(context.Background(), config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	var logs bytes.Buffer
	rc := Recorder{Audit: audit.NewLog(db), Log: slog.New(slog.NewTextHandler(&logs, nil))}
	req := httptest.NewRequest("POST", "/api/v1/things", nil)
	req.Pattern = "POST /api/v1/things"
	rc.Record(req, ActorFor(req).Event("thing.create", "thing", "", audit.Success, map[string]string{"secretish": "do-not-log"}))

	out := logs.String()
	for _, want := range []string{"audit record failed", "action=thing.create", `route="POST /api/v1/things"`, "err="} {
		if !strings.Contains(out, want) {
			t.Fatalf("log line missing %q: %s", want, out)
		}
	}
	if strings.Contains(out, "do-not-log") {
		t.Fatalf("event details leaked into the log: %s", out)
	}
}

// TestActorFor: the client address always, the user only when a principal is
// present; a request without one must not panic.
func TestActorFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.7:1234"
	if a := ActorFor(req); a.UserID != "" || a.IP != "198.51.100.7" {
		t.Fatalf("anonymous actor = %+v, want IP only", a)
	}

	ctx := context.WithValue(req.Context(), principalKey, &Principal{User: &user.User{ID: "u1"}})
	if a := ActorFor(req.WithContext(ctx)); a.UserID != "u1" || a.IP != "198.51.100.7" {
		t.Fatalf("signed-in actor = %+v, want u1@198.51.100.7", a)
	}

	// Behind a trusted proxy ClientIP resolves to the forwarded address;
	// the actor follows it.
	ctx = WithClientIP(req.Context(), "203.0.113.5")
	if a := ActorFor(req.WithContext(ctx)); a.IP != "203.0.113.5" {
		t.Fatalf("proxied actor = %+v, want 203.0.113.5", a)
	}
}
