// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/store"
)

// send makes a request as who, with their CSRF token and an optional JSON body.
func (e *env) send(method, path, who string, body any) (*httptest.ResponseRecorder, map[string]any) {
	var buf io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, buf)
	req.RemoteAddr = "203.0.113.9:4321"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-CSRF-Token", e.csrf[who])
	req.AddCookie(e.cookies[who])
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

func (e *env) lastEvent(t *testing.T, action string) audit.Event {
	t.Helper()
	evs, _, err := e.audit.List(context.Background(), audit.Filter{Action: action, Limit: 1})
	if err != nil || len(evs) == 0 {
		t.Fatalf("no %s event: %v", action, err)
	}
	return evs[0]
}

func (e *env) sessionOf(t *testing.T, recID string) *Session {
	t.Helper()
	rec, err := e.repo.GetRecording(context.Background(), recID)
	if err != nil {
		t.Fatal(err)
	}
	s, err := e.repo.Get(context.Background(), rec.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSessionLists: a user sees only their own sessions and never a
// recording id (ADR 0006); reviewers see everyone's; a plain user cannot
// list everyone's.
func TestSessionLists(t *testing.T) {
	e := newEnv(t)
	recID := e.record(t, "asciicast")
	other := &Session{UserID: e.ids["reviewer"], TargetID: "t1", Protocol: "ssh", ClientIP: "10.0.0.2"}
	if err := e.repo.Start(context.Background(), other); err != nil {
		t.Fatal(err)
	}

	rr, out := e.get("/api/v1/me/sessions", "alice")
	items, _ := out["items"].([]any)
	if rr.Code != http.StatusOK || len(items) != 1 {
		t.Fatalf("alice's own sessions: %d %v", rr.Code, out)
	}
	mine := items[0].(map[string]any)
	if mine["user_id"] != e.ids["alice"] || mine["recording_id"] != nil {
		t.Fatalf("alice sees %v; want only her session, without a recording id", mine)
	}

	for _, who := range []string{"root", "reviewer"} {
		rr, out := e.get("/api/v1/sessions", who)
		if items, _ := out["items"].([]any); rr.Code != http.StatusOK || len(items) != 2 {
			t.Errorf("%s listing all sessions: %d %v", who, rr.Code, out)
		}
	}
	if rr, out := e.get("/api/v1/sessions?open=true", "reviewer"); len(out["items"].([]any)) != 1 || rr.Code != http.StatusOK {
		t.Errorf("open sessions only: %v", out)
	}
	if rr, _ := e.get("/api/v1/sessions", "alice"); rr.Code != http.StatusForbidden {
		t.Errorf("alice listing everyone's sessions: %d, want 403", rr.Code)
	}

	sid := e.sessionOf(t, recID).ID
	if rr, out := e.get("/api/v1/sessions/"+sid, "reviewer"); rr.Code != http.StatusOK || out["id"] != sid {
		t.Errorf("get session: %d %v", rr.Code, out)
	}
	if rr, _ := e.get("/api/v1/sessions/no-such-session", "reviewer"); rr.Code != http.StatusNotFound {
		t.Errorf("unknown session: %d, want 404", rr.Code)
	}
}

// TestRecordingPlayback: a reviewer gets a recording's metadata with its
// session, and every stream is a recorded view and an audit event naming the
// viewer; a plain user cannot watch; a purged recording is gone.
func TestRecordingPlayback(t *testing.T) {
	e := newEnv(t)
	recID := e.record(t, "asciicast")
	rec, _ := e.repo.GetRecording(context.Background(), recID)

	rr, out := e.get("/api/v1/recordings/"+recID, "reviewer")
	if sess, _ := out["session"].(map[string]any); rr.Code != http.StatusOK || sess["user_id"] != e.ids["alice"] {
		t.Fatalf("recording metadata: %d %v", rr.Code, out)
	}

	rr, _ = e.get("/api/v1/recordings/"+recID+"/stream", "reviewer")
	want, _ := os.ReadFile(strings.TrimPrefix(rec.StorageURI, "file://"))
	if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), want) {
		t.Fatalf("stream: %d, %d bytes, want %d", rr.Code, rr.Body.Len(), len(want))
	}
	if rr.Header().Get("X-Recording-SHA256") != rec.SHA256 || !strings.HasPrefix(rr.Header().Get("Content-Type"), "application/x-asciicast") {
		t.Fatalf("stream headers %v", rr.Header())
	}
	ev := e.lastEvent(t, "recording.view")
	if ev.ActorUserID != e.ids["reviewer"] || ev.ObjectID != recID {
		t.Fatalf("recording.view by %s for %s", ev.ActorUserID, ev.ObjectID)
	}
	var views int
	if err := e.db.QueryRowContext(context.Background(), e.db.Rebind(`SELECT COUNT(*) FROM recording_views WHERE recording_id = ? AND user_id = ?`), recID, e.ids["reviewer"]).Scan(&views); err != nil || views != 1 {
		t.Fatalf("views recorded: %d %v", views, err)
	}

	for _, path := range []string{"/api/v1/recordings/" + recID, "/api/v1/recordings/" + recID + "/stream"} {
		if rr, _ := e.get(path, "alice"); rr.Code != http.StatusForbidden {
			t.Errorf("alice %s: %d, want 403", path, rr.Code)
		}
	}
	if rr, _ := e.get("/api/v1/recordings/no-such-recording/stream", "reviewer"); rr.Code != http.StatusNotFound {
		t.Errorf("unknown recording: %d, want 404", rr.Code)
	}

	if _, err := e.db.ExecContext(context.Background(), e.db.Rebind(`UPDATE recordings SET purged_at = ? WHERE id = ?`), store.TimeArg(rec.CreatedAt), recID); err != nil {
		t.Fatal(err)
	}
	if rr, out := e.get("/api/v1/recordings/"+recID+"/stream", "reviewer"); rr.Code != http.StatusGone || out["code"] != "purged" {
		t.Fatalf("purged recording: %d %v, want 410 purged", rr.Code, out)
	}
}

// TestTerminateSession: an admin ends an open session (closing its row when
// it is not live here) and the act is audited with the session's owner; an
// ended session cannot be ended twice; a reviewer cannot terminate.
func TestTerminateSession(t *testing.T) {
	e := newEnv(t)
	s := &Session{UserID: e.ids["alice"], TargetID: "t1", Protocol: "ssh", ClientIP: "10.0.0.1"}
	if err := e.repo.Start(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/sessions/" + s.ID + "/terminate"

	if rr, _ := e.send("POST", path, "reviewer", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("reviewer terminating: %d, want 403", rr.Code)
	}
	if rr, out := e.send("POST", path, "root", map[string]string{"reason": "incident 42"}); rr.Code != http.StatusOK || out["live"] != false {
		t.Fatalf("terminate: %d %v", rr.Code, out)
	}
	got, _ := e.repo.Get(context.Background(), s.ID)
	if got.EndedAt == nil || got.EndReason != EndAdminTerminated {
		t.Fatalf("session after terminate: %+v", got)
	}
	ev := e.lastEvent(t, "session.terminate")
	var d map[string]any
	_ = json.Unmarshal(ev.Details, &d)
	if ev.ActorUserID != e.ids["root"] || d["target_user_id"] != e.ids["alice"] || d["reason"] != "incident 42" {
		t.Fatalf("session.terminate by %s: %v", ev.ActorUserID, d)
	}
	if rr, out := e.send("POST", path, "root", nil); rr.Code != http.StatusConflict || out["code"] != "already_ended" {
		t.Fatalf("terminate twice: %d %v", rr.Code, out)
	}
	if rr, _ := e.send("POST", "/api/v1/sessions/no-such-session/terminate", "root", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("terminate unknown: %d, want 404", rr.Code)
	}
}

// TestAuditLogRoutes: reviewers read the log with names resolved, and each
// read is itself audited; a plain user cannot read it; filters by a name a
// reviewer knows, and an unknown name matches nothing rather than
// everything; verify reports an intact chain and a tampered one.
func TestAuditLogRoutes(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, who := range []string{"alice", "reviewer"} {
		if _, err := e.audit.Record(ctx, audit.Actor{UserID: e.ids[who], IP: "203.0.113.9"}.Event("user.login", "user", e.ids[who], audit.Success, nil)); err != nil {
			t.Fatal(err)
		}
	}

	rr, out := e.get("/api/v1/audit/events?action=user.login", "reviewer")
	items, _ := out["items"].([]any)
	if rr.Code != http.StatusOK || len(items) != 2 {
		t.Fatalf("read the log: %d %v", rr.Code, out)
	}
	if first := items[0].(map[string]any); first["actor_username"] == nil || first["object_name"] == nil {
		t.Fatalf("names not resolved: %v", first)
	}
	if ev := e.lastEvent(t, "audit.read"); ev.ActorUserID != e.ids["reviewer"] {
		t.Fatalf("audit.read by %s, want the reviewer", ev.ActorUserID)
	}

	if rr, out := e.get("/api/v1/audit/events?action=user.login&actor=alice", "root"); rr.Code != http.StatusOK || len(out["items"].([]any)) != 1 {
		t.Errorf("filter by actor name: %d %v", rr.Code, out)
	}
	if _, out := e.get("/api/v1/audit/events?actor=nobody", "root"); len(out["items"].([]any)) != 0 {
		t.Errorf("an unknown actor must match nothing, got %v", out["items"])
	}
	if rr, _ := e.get("/api/v1/audit/events?exclude=DROP%20TABLE", "root"); rr.Code != http.StatusBadRequest {
		t.Errorf("a malformed exclude token: %d, want 400", rr.Code)
	}
	if rr, out := e.get("/api/v1/audit/facets", "reviewer"); rr.Code != http.StatusOK || out["actions"] == nil {
		t.Errorf("facets: %d %v", rr.Code, out)
	}
	for _, path := range []string{"/api/v1/audit/events", "/api/v1/audit/verify", "/api/v1/audit/facets"} {
		if rr, _ := e.get(path, "alice"); rr.Code != http.StatusForbidden {
			t.Errorf("alice %s: %d, want 403", path, rr.Code)
		}
	}

	if _, out := e.get("/api/v1/audit/verify", "reviewer"); out["intact"] != true {
		t.Fatalf("verify an intact log: %v", out)
	}
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`UPDATE audit_events SET actor_ip = ? WHERE action = ?`), "198.51.100.1", "user.login"); err != nil {
		t.Fatal(err)
	}
	if _, out := e.get("/api/v1/audit/verify", "reviewer"); out["intact"] != false || out["broken"] == nil {
		t.Fatalf("verify a tampered log: %v", out)
	}
}

// TestRetentionPolicy: only an admin reads or changes the retention policy;
// negative values are refused; a change is saved and audited.
func TestRetentionPolicy(t *testing.T) {
	e := newEnv(t)
	path := "/api/v1/admin/retention"
	if rr, _ := e.get(path, "root"); rr.Code != http.StatusOK {
		t.Fatalf("read retention: %d", rr.Code)
	}
	if rr, _ := e.send("PUT", path, "root", map[string]int{"max_age_days": -1}); rr.Code != http.StatusBadRequest {
		t.Fatalf("negative retention: %d, want 400", rr.Code)
	}
	rr, out := e.send("PUT", path, "root", map[string]int{"max_age_days": 90, "max_total_bytes": 1 << 30})
	if rr.Code != http.StatusOK || out["max_age_days"] != float64(90) {
		t.Fatalf("set retention: %d %v", rr.Code, out)
	}
	ev := e.lastEvent(t, "retention.policy.update")
	var d map[string]any
	_ = json.Unmarshal(ev.Details, &d)
	if ev.ActorUserID != e.ids["root"] || d["max_age_days"] != float64(90) {
		t.Fatalf("retention.policy.update by %s: %v", ev.ActorUserID, d)
	}
	for _, who := range []string{"reviewer", "alice"} {
		if rr, _ := e.send("PUT", path, who, map[string]int{"max_age_days": 1}); rr.Code != http.StatusForbidden {
			t.Errorf("%s changing retention: %d, want 403", who, rr.Code)
		}
	}
}
