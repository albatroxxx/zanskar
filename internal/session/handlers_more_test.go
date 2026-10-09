// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/store"
)

// exec runs a statement against the test database or fails the test. Tests
// use it to break one table on purpose (rename it, or add a trigger that
// aborts writes) so a handler's storage-error path runs for real.
func (e *env) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := e.db.ExecContext(context.Background(), e.db.Rebind(q), args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// failWrites makes every op (INSERT or UPDATE) on table abort.
func (e *env) failWrites(t *testing.T, table, op string) {
	t.Helper()
	e.exec(t, fmt.Sprintf(`CREATE TRIGGER fail_%s_%s BEFORE %s ON %s BEGIN SELECT RAISE(ABORT, 'injected failure'); END`, strings.ToLower(op), table, op, table))
}

// raw sends a request with a literal body as who.
func (e *env) raw(method, path, who, body string) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "203.0.113.9:4321"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf[who])
	req.AddCookie(e.cookies[who])
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

func (e *env) countEvents(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := e.db.QueryRowContext(context.Background(), e.db.Rebind(`SELECT COUNT(*) FROM audit_events WHERE action = ?`), action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) countViews(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM recording_views`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// wantInternal asserts a generic 500 that leaks nothing of the cause.
func wantInternal(t *testing.T, what string, rr *httptest.ResponseRecorder, out map[string]any) {
	t.Helper()
	if rr.Code != http.StatusInternalServerError || out["code"] != "internal" {
		t.Fatalf("%s: %d %v, want 500 internal", what, rr.Code, out)
	}
	if strings.Contains(rr.Body.String(), "injected") || strings.Contains(rr.Body.String(), "no such table") {
		t.Fatalf("%s: storage error leaked to the client: %s", what, rr.Body.String())
	}
}

// TestSessionListsStorageError: when the sessions table cannot be read, the
// user's own list and the reviewer list answer 500 without the cause.
func TestSessionListsStorageError(t *testing.T) {
	e := newEnv(t)
	e.exec(t, `ALTER TABLE access_sessions RENAME TO access_sessions_gone`)
	rr, out := e.get("/api/v1/me/sessions", "alice")
	wantInternal(t, "me/sessions", rr, out)
	rr, out = e.get("/api/v1/sessions", "reviewer")
	wantInternal(t, "sessions", rr, out)
}

// TestTerminateRefusesBadBodyAndKeepsSessionOpen: a malformed body is a 400,
// the session stays open, and nothing is audited.
func TestTerminateRefusesBadBodyAndKeepsSessionOpen(t *testing.T) {
	e := newEnv(t)
	s := &Session{UserID: e.ids["alice"], TargetID: "t1", Protocol: "ssh", ClientIP: "10.0.0.1"}
	if err := e.repo.Start(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/sessions/" + s.ID + "/terminate"
	if rr, out := e.raw("POST", path, "root", `{"reason":`); rr.Code != http.StatusBadRequest || out["code"] != "bad_request" {
		t.Fatalf("malformed body: %d %v, want 400", rr.Code, out)
	}
	if rr, _ := e.raw("POST", path, "root", `{"reason":"x","surprise":1}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d, want 400", rr.Code)
	}
	got, _ := e.repo.Get(context.Background(), s.ID)
	if got.EndedAt != nil {
		t.Fatalf("a refused terminate must leave the session open: %+v", got)
	}
	if n := e.countEvents(t, "session.terminate"); n != 0 {
		t.Fatalf("refused terminate audited %d times", n)
	}
}

// TestTerminateCloseFails: when closing the row fails, the admin gets a 500
// and no session.terminate event claims it happened.
func TestTerminateCloseFails(t *testing.T) {
	e := newEnv(t)
	s := &Session{UserID: e.ids["alice"], TargetID: "t1", Protocol: "ssh", ClientIP: "10.0.0.1"}
	if err := e.repo.Start(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	e.failWrites(t, "access_sessions", "UPDATE")
	rr, out := e.send("POST", "/api/v1/sessions/"+s.ID+"/terminate", "root", map[string]string{"reason": "x"})
	wantInternal(t, "terminate", rr, out)
	if n := e.countEvents(t, "session.terminate"); n != 0 {
		t.Fatalf("failed terminate audited %d times", n)
	}
}

// TestGetRecordingErrors: an unknown recording is 404; a recording whose
// session row cannot be read is a 500, not a recording without a session.
func TestGetRecordingErrors(t *testing.T) {
	e := newEnv(t)
	recID := e.record(t, "asciicast")
	if rr, out := e.get("/api/v1/recordings/no-such-recording", "reviewer"); rr.Code != http.StatusNotFound || out["code"] != "not_found" {
		t.Fatalf("unknown recording: %d %v", rr.Code, out)
	}
	e.exec(t, `ALTER TABLE access_sessions RENAME TO access_sessions_gone`)
	rr, out := e.get("/api/v1/recordings/"+recID, "reviewer")
	wantInternal(t, "recording metadata", rr, out)
}

// TestStreamRecordingFailures: a view that cannot be recorded is not served
// and not audited; a recording whose data is gone from storage is a 404
// "recording data unavailable", and is neither a view nor audited as one.
func TestStreamRecordingFailures(t *testing.T) {
	e := newEnv(t)
	recID := e.record(t, "asciicast")
	rec, _ := e.repo.GetRecording(context.Background(), recID)

	e.failWrites(t, "recording_views", "INSERT")
	rr, out := e.get("/api/v1/recordings/"+recID+"/stream", "reviewer")
	wantInternal(t, "stream without a recorded view", rr, out)
	if n := e.countEvents(t, "recording.view"); n != 0 {
		t.Fatalf("an unrecorded view must not be audited as a view: %d events", n)
	}
	e.exec(t, `DROP TRIGGER fail_insert_recording_views`)

	if err := os.Remove(strings.TrimPrefix(rec.StorageURI, "file://")); err != nil {
		t.Fatal(err)
	}
	rr, out = e.get("/api/v1/recordings/"+recID+"/stream", "reviewer")
	if rr.Code != http.StatusNotFound || out["message"] != "recording data unavailable" {
		t.Fatalf("missing blob: %d %v", rr.Code, out)
	}
	if n := e.countEvents(t, "recording.view"); n != 0 {
		t.Fatalf("a view of missing data must not be audited as a view: %d events", n)
	}
	if n := e.countViews(t); n != 0 {
		t.Fatalf("a view of missing data must not be recorded: %d views", n)
	}
}

// TestDownloadRecordingFailures covers the evidence download's refusals: an
// unknown id is 404, a purged recording is 410 and not counted as a view, a
// view that cannot be recorded is a 500, an unreadable session is a 500, and
// a blob missing from storage is a 404 naming the data that is neither a view
// nor a successful download in the audit log.
func TestDownloadRecordingFailures(t *testing.T) {
	e := newEnv(t)
	recID := e.record(t, "guac")
	rec, _ := e.repo.GetRecording(context.Background(), recID)
	path := "/api/v1/recordings/" + recID + "/download"

	if rr, _ := e.get("/api/v1/recordings/no-such-recording/download", "reviewer"); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown recording: %d, want 404", rr.Code)
	}

	// The guac recording's size and hash travel as headers.
	rr, _ := e.get(path, "reviewer")
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/octet-stream" ||
		rr.Header().Get("Content-Length") != "24" || rr.Header().Get("X-Recording-SHA256") != "deadbeef" {
		t.Fatalf("desktop download headers: %d %v", rr.Code, rr.Header())
	}
	if rr.Body.String() != "4.size,1.0,4.1024,3.768;" {
		t.Fatalf("desktop download body: %q", rr.Body.String())
	}
	views := e.countViews(t)

	e.failWrites(t, "recording_views", "INSERT")
	rr, out := e.get(path, "reviewer")
	wantInternal(t, "download without a recorded view", rr, out)
	e.exec(t, `DROP TRIGGER fail_insert_recording_views`)

	if err := os.Remove(strings.TrimPrefix(rec.StorageURI, "file://")); err != nil {
		t.Fatal(err)
	}
	downloads := e.countEvents(t, "recording.download")
	if rr, out := e.get(path, "reviewer"); rr.Code != http.StatusNotFound || out["message"] != "recording data unavailable" {
		t.Fatalf("missing blob: %d %v", rr.Code, out)
	}
	// Nothing was seen, so nothing is logged as seen.
	if got := e.countViews(t); got != views {
		t.Fatalf("a download of missing data must not be a view: %d views, want %d", got, views)
	}
	if got := e.countEvents(t, "recording.download"); got != downloads {
		t.Fatalf("a download of missing data must not be audited as a success: %d events, want %d", got, downloads)
	}

	e.exec(t, `UPDATE recordings SET purged_at = ? WHERE id = ?`, store.TimeArg(time.Now()), recID)
	if rr, out := e.get(path, "reviewer"); rr.Code != http.StatusGone || out["code"] != "purged" {
		t.Fatalf("purged download: %d %v, want 410", rr.Code, out)
	}
	if got := e.countViews(t); got != views {
		t.Fatalf("a refused purged download must not be a view: %d views, want %d", got, views)
	}
	e.exec(t, `UPDATE recordings SET purged_at = NULL WHERE id = ?`, recID)

	e.exec(t, `ALTER TABLE access_sessions RENAME TO access_sessions_gone`)
	rr, out = e.get(path, "reviewer")
	wantInternal(t, "download with an unreadable session", rr, out)
}

// TestDownloadTranscriptFailures: an unknown id is 404, a purged terminal
// recording is 410, a missing blob is 404, and a blob that cannot be parsed
// (one line over the 4 MiB scanner cap) is a 500.
func TestDownloadTranscriptFailures(t *testing.T) {
	e := newEnv(t)
	recID := e.record(t, "asciicast")
	rec, _ := e.repo.GetRecording(context.Background(), recID)
	path := "/api/v1/recordings/" + recID + "/transcript"
	file := strings.TrimPrefix(rec.StorageURI, "file://")

	if rr, out := e.get("/api/v1/recordings/no-such-recording/transcript", "reviewer"); rr.Code != http.StatusNotFound || out["code"] != "not_found" {
		t.Fatalf("unknown recording: %d %v", rr.Code, out)
	}

	huge := append([]byte{'['}, bytes.Repeat([]byte{'x'}, 5<<20)...)
	if err := os.WriteFile(file, huge, 0o600); err != nil {
		t.Fatal(err)
	}
	rr, out := e.get(path, "reviewer")
	wantInternal(t, "unparseable transcript", rr, out)

	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if rr, out := e.get(path, "reviewer"); rr.Code != http.StatusNotFound || out["message"] != "recording data unavailable" {
		t.Fatalf("missing blob: %d %v", rr.Code, out)
	}

	e.exec(t, `UPDATE recordings SET purged_at = ? WHERE id = ?`, store.TimeArg(time.Now()), recID)
	if rr, out := e.get(path, "reviewer"); rr.Code != http.StatusGone || out["code"] != "purged" {
		t.Fatalf("purged transcript: %d %v, want 410", rr.Code, out)
	}
}

// TestTranscriptAutoscalingSession: a session on an autoscaling instance has
// no target name, so the transcript header and file name use the group and
// the cloud instance id instead.
func TestTranscriptAutoscalingSession(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := store.TimeArg(time.Now())
	e.exec(t, `INSERT INTO autoscaling_groups (id, name, provider, region, external_name, role_arn, external_id, os_family, created_at, updated_at)
		VALUES ('g1', 'web-asg', 'aws', 'us-east-1', 'web', 'arn:aws:iam::1:role/z', 'ext', 'linux', ?, ?)`, now, now)
	e.exec(t, `INSERT INTO asg_instances (id, asg_id, instance_id, lifecycle_state, first_seen_at, last_seen_at)
		VALUES ('ai1', 'g1', 'i-0abc', 'InService', ?, ?)`, now, now)
	s := &Session{UserID: e.ids["alice"], ASGID: "g1", ASGInstanceID: "ai1", Protocol: "ssh", ClientIP: "10.0.0.1"}
	if err := e.repo.Start(ctx, s); err != nil {
		t.Fatal(err)
	}
	cast, uri, err := recordingAsciicast(ctx, e, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec := &Recording{SessionID: s.ID, Format: "asciicast", StorageURI: uri}
	if err := e.repo.CreateRecording(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := e.repo.FinishRecording(ctx, rec.ID, cast.size, cast.sum); err != nil {
		t.Fatal(err)
	}

	rr, _ := e.get("/api/v1/recordings/"+rec.ID+"/transcript", "reviewer")
	if rr.Code != http.StatusOK {
		t.Fatalf("transcript: %d %s", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); !strings.Contains(body, "# alice on web-asg i-0abc (SSH)") || !strings.Contains(body, "uptime") {
		t.Fatalf("autoscaling transcript header:\n%s", body)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, `attachment; filename="alice-i-0abc-`) {
		t.Fatalf("autoscaling attachment name: %q", cd)
	}
}

type castResult struct {
	size int64
	sum  string
}

// recordingAsciicast writes a one-command terminal recording for a session.
func recordingAsciicast(ctx context.Context, e *env, sessionID string) (castResult, string, error) {
	cast, uri, err := recording.NewAsciicast(ctx, e.storage, sessionID+".cast", recording.Header{Width: 80, Height: 24, Title: "test"})
	if err != nil {
		return castResult{}, "", err
	}
	_ = cast.Marker("uptime")
	size, sum, err := cast.Close()
	return castResult{size, sum}, uri, err
}

// TestAuditEventsFiltersAndDecoration: ids inside details are labelled with
// names (a target id named as the target, an autoscaling instance id via the
// fallback kind); exclude drops matching actions; time bounds apply and a
// malformed bound is ignored; more than 16 exclude tokens are refused.
func TestAuditEventsFiltersAndDecoration(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := store.TimeArg(time.Now())
	e.exec(t, `INSERT INTO autoscaling_groups (id, name, provider, region, external_name, role_arn, external_id, os_family, created_at, updated_at)
		VALUES ('g1', 'web-asg', 'aws', 'us-east-1', 'web', 'arn:aws:iam::1:role/z', 'ext', 'linux', ?, ?)`, now, now)
	e.exec(t, `INSERT INTO asg_instances (id, asg_id, instance_id, lifecycle_state, first_seen_at, last_seen_at)
		VALUES ('ai1', 'g1', 'i-0abc', 'InService', ?, ?)`, now, now)
	alice := audit.Actor{UserID: e.ids["alice"], IP: "203.0.113.9"}
	for _, ev := range []audit.Event{
		alice.Event("connect.start", "user", e.ids["alice"], audit.Success, map[string]any{"target_id": "t1"}),
		alice.Event("connect.start", "user", e.ids["alice"], audit.Success, map[string]any{"target_id": "ai1", "asg_id": "g1"}),
		alice.Event("connect.start", "user", e.ids["alice"], audit.Failure, map[string]any{"target_id": "gone"}),
		alice.Event("user.login", "user", e.ids["alice"], audit.Success, nil),
	} {
		if _, err := e.audit.Record(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}

	_, out := e.get("/api/v1/audit/events?action=connect.start", "reviewer")
	items, _ := out["items"].([]any)
	if len(items) != 3 {
		t.Fatalf("connect events: %v", out)
	}
	labels := map[string]map[string]any{}
	for _, it := range items {
		row := it.(map[string]any)
		var d map[string]any
		_ = json.Unmarshal(mustJSON(t, row["details"]), &d)
		dn, _ := row["details_names"].(map[string]any)
		labels[d["target_id"].(string)] = dn
	}
	if labels["t1"]["target_id"] != "web 1" {
		t.Errorf("static target label: %v", labels["t1"])
	}
	if labels["ai1"]["target_id"] != "i-0abc" || labels["ai1"]["asg_id"] != "web-asg" {
		t.Errorf("autoscaling instance label: %v", labels["ai1"])
	}
	if labels["gone"] != nil {
		t.Errorf("an unknown id must stay unlabelled: %v", labels["gone"])
	}

	_, out = e.get("/api/v1/audit/events?actor=alice&exclude=connect.start:failure,%20user.login", "reviewer")
	items, _ = out["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("exclude failures and logins: want 2 rows, got %v", out)
	}
	for _, it := range items {
		row := it.(map[string]any)
		if row["action"] != "connect.start" || row["outcome"] != "success" {
			t.Errorf("excluded row returned: %v", row)
		}
	}

	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if _, out := e.get("/api/v1/audit/events?actor=alice&from="+future, "reviewer"); len(out["items"].([]any)) != 0 {
		t.Errorf("from in the future must match nothing: %v", out["items"])
	}
	if _, out := e.get("/api/v1/audit/events?actor=alice&to="+past, "reviewer"); len(out["items"].([]any)) != 0 {
		t.Errorf("to in the past must match nothing: %v", out["items"])
	}
	if _, out := e.get("/api/v1/audit/events?actor=alice&from=yesterday&to=later", "reviewer"); len(out["items"].([]any)) != 4 {
		t.Errorf("malformed bounds are ignored: %v", out["items"])
	}

	toks := make([]string, 17)
	for i := range toks {
		toks[i] = fmt.Sprintf("a%d", i)
	}
	if rr, _ := e.get("/api/v1/audit/events?exclude="+strings.Join(toks[:16], ","), "reviewer"); rr.Code != http.StatusOK {
		t.Errorf("16 exclude tokens: %d, want 200", rr.Code)
	}
	if rr, out := e.get("/api/v1/audit/events?exclude="+strings.Join(toks, ","), "reviewer"); rr.Code != http.StatusBadRequest || out["code"] != "bad_request" {
		t.Errorf("17 exclude tokens: %d %v, want 400", rr.Code, out)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestAuditRoutesStorageErrors: when the log cannot be read the events,
// verify and facets routes answer 500, and a name lookup that fails while
// decorating rows fails the page rather than returning it half-labelled.
func TestAuditRoutesStorageErrors(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.audit.Record(ctx, audit.Actor{UserID: e.ids["alice"]}.Event("credential.create", "credential", "c1", audit.Success, nil)); err != nil {
		t.Fatal(err)
	}
	e.exec(t, `ALTER TABLE credentials RENAME TO credentials_gone`)
	rr, out := e.get("/api/v1/audit/events", "reviewer")
	wantInternal(t, "events with a failing name lookup", rr, out)
	if n := e.countEvents(t, "audit.read"); n != 0 {
		t.Fatalf("a failed read must not be audited as a read: %d", n)
	}

	e.exec(t, `ALTER TABLE audit_events RENAME TO audit_events_gone`)
	for _, p := range []string{"/api/v1/audit/events", "/api/v1/audit/verify", "/api/v1/audit/facets"} {
		rr, out := e.get(p, "reviewer")
		wantInternal(t, p, rr, out)
	}
}

// TestRetentionErrors: a malformed body is a 400 and changes nothing; a
// negative byte cap is refused like a negative age; a storage failure on
// read or write is a 500, and a failed write is not audited.
func TestRetentionErrors(t *testing.T) {
	e := newEnv(t)
	path := "/api/v1/admin/retention"
	if rr, _ := e.raw("PUT", path, "root", `{"max_age_days":"ninety"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed body: %d, want 400", rr.Code)
	}
	if rr, out := e.send("PUT", path, "root", map[string]int64{"max_total_bytes": -5}); rr.Code != http.StatusBadRequest || out["message"] != "retention values must not be negative" {
		t.Fatalf("negative byte cap: %d %v", rr.Code, out)
	}
	if p, _ := e.repo.GetRetentionPolicy(context.Background()); p.MaxAgeDays != 0 || p.MaxTotalBytes != 0 || p.UpdatedAt != nil {
		t.Fatalf("refused updates changed the policy: %+v", p)
	}

	e.failWrites(t, "retention_policy", "INSERT")
	rr, out := e.send("PUT", path, "root", map[string]int{"max_age_days": 30})
	wantInternal(t, "set retention", rr, out)
	if n := e.countEvents(t, "retention.policy.update"); n != 0 {
		t.Fatalf("a failed update audited %d times", n)
	}

	e.exec(t, `ALTER TABLE retention_policy RENAME TO retention_policy_gone`)
	rr, out = e.get(path, "root")
	wantInternal(t, "get retention", rr, out)
}

// TestAuditWriteFailureIsLogged: when the audit log cannot be written the
// action itself still completes (the failure is logged server-side).
func TestAuditWriteFailureIsLogged(t *testing.T) {
	e := newEnv(t)
	e.failWrites(t, "audit_events", "INSERT")
	rr, out := e.send("PUT", "/api/v1/admin/retention", "root", map[string]int{"max_age_days": 7})
	if rr.Code != http.StatusOK || out["max_age_days"] != float64(7) {
		t.Fatalf("set retention with a failing audit log: %d %v", rr.Code, out)
	}
	if n := e.countEvents(t, "retention.policy.update"); n != 0 {
		t.Fatalf("the trigger should have blocked the event: %d", n)
	}
}
