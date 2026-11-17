// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/cloud"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/policy/policytest"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
)

const (
	testRoleARN  = "arn:aws:iam::123456789012:role/Admin"
	testGateway  = "https://gw.example"
	testAssumeOK = "arn:aws:sts::123456789012:assumed-role/Admin/"
)

// fakeMinter stands in for STS (ADR 0050): it records every mint a session
// asks for and answers credentials that end when the request said, on the
// package clock, so a test that moves the clock moves their end.
type fakeMinter struct {
	mu       sync.Mutex
	requests []cloud.MintRequest
	err      error
	n        int
}

func (m *fakeMinter) Mint(_ context.Context, req cloud.MintRequest) (cloud.Credentials, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, req)
	if m.err != nil {
		return cloud.Credentials{}, m.err
	}
	m.n++
	return cloud.Credentials{AccessKeyID: "ASIA" + strings.Repeat("0", 9) + string(rune('A'+m.n-1)), SecretAccessKey: "secret-" + string(rune('A'+m.n-1)), SessionToken: "token-" + string(rune('A'+m.n-1)),
		Expires: cloudNow().Add(req.Duration), AssumedARN: testAssumeOK + req.SessionName}, nil
}

func (m *fakeMinter) CallerIdentity(_ context.Context, c cloud.Credentials) (string, error) {
	return c.AssumedARN, nil
}

func (m *fakeMinter) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.requests)
}

func (m *fakeMinter) last() cloud.MintRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests[len(m.requests)-1]
}

func (m *fakeMinter) fail(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

// fakeFederation is AWS's sign-in endpoint: it records what the gateway
// asked and can refuse SessionDuration or everything.
type fakeFederation struct {
	mu             sync.Mutex
	calls          []map[string]string
	refuseDuration bool
	status         int
	srv            *httptest.Server
}

func (f *fakeFederation) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	call := map[string]string{}
	for k := range q {
		call[k] = q.Get(k)
	}
	f.mu.Lock()
	f.calls = append(f.calls, call)
	refuse, status := f.refuseDuration && q.Get("SessionDuration") != "", f.status
	f.mu.Unlock()
	switch {
	case status != 0:
		w.WriteHeader(status)
	case refuse:
		w.WriteHeader(http.StatusBadRequest)
	default:
		_ = json.NewEncoder(w).Encode(map[string]string{"SigninToken": "signin-token-" + q.Get("SessionDuration")})
	}
}

func (f *fakeFederation) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeFederation) call(i int) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[i]
}

// cloudFixture is the connect fixture with a cloud account's role enrolled,
// a fake STS and a fake federation endpoint, and a policy granting ops the
// role with both doors open.
type cloudFixture struct {
	*connectFixture
	minter *fakeMinter
	fed    *fakeFederation
	role   *target.Target
	policy *policy.Policy
	recDir string
}

func newCloudFixture(t *testing.T) *cloudFixture {
	t.Helper()
	f := newConnectFixture(t)
	dir := t.TempDir()
	f.h.Registry = gateway.NewRegistry()
	f.h.Storage = &recording.LocalStorage{Dir: dir}
	f.h.PublicURL = testGateway
	minter := &fakeMinter{}
	f.h.NewMinter = func(_ context.Context, region string) (cloud.RoleMinter, error) {
		if region != "eu-west-1" {
			t.Errorf("the minter was asked for region %q", region)
		}
		return minter, nil
	}
	fed := &fakeFederation{}
	fed.srv = httptest.NewServer(fed)
	t.Cleanup(fed.srv.Close)
	f.h.Federation = &cloud.Federation{Endpoint: fed.srv.URL, Client: fed.srv.Client()}
	// No session outlives its test: one left live would keep its goroutine
	// reading the package clock the next test moves (the kube fixture's
	// lesson, PR #336).
	t.Cleanup(func() {
		for _, l := range f.h.Registry.List() {
			f.h.Registry.Terminate(l.SessionID)
		}
		for i := 0; i < 300 && f.h.CloudSessions() > 0; i++ {
			time.Sleep(10 * time.Millisecond)
		}
	})
	tg := &target.Target{Name: "Prod Admin", CloudRoleARN: testRoleARN, CloudAccountAlias: "prod", CloudRegion: "eu-west-1", Tags: map[string]string{"account": "prod"}}
	if err := f.h.Targets.Create(f.ctx, tg); err != nil {
		t.Fatal(err)
	}
	p := policytest.Policy("aws-prod", []policy.Subject{policytest.Group(f.opsID)}, policytest.Named(protocol.KindCloud, []string{tg.ID}, "cloud"))
	if err := f.h.Policies.Create(f.ctx, p); err != nil {
		t.Fatal(err)
	}
	return &cloudFixture{connectFixture: f, minter: minter, fed: fed, role: tg, policy: p, recDir: dir}
}

// switches sets the policy's cloud grant to the doors given.
func (f *cloudFixture) switches(t *testing.T, console, cli bool) {
	t.Helper()
	f.policy.Grants[0].CloudConsole, f.policy.Grants[0].CloudCLI = &console, &cli
	if err := f.h.Policies.Update(f.ctx, f.policy); err != nil {
		t.Fatal(err)
	}
}

// connectCloud starts a cloud session as alice and returns its id, its token
// and the answer's cloud object.
func (f *cloudFixture) connectCloud(t *testing.T) (sid, token string, c map[string]any) {
	t.Helper()
	code, out := f.connect(t, map[string]any{"target_id": f.role.ID, "protocol": "cloud"})
	if code != http.StatusOK {
		t.Fatalf("connect: %d %v", code, out)
	}
	sid, _ = out["session_id"].(string)
	c, _ = out["cloud"].(map[string]any)
	if sid == "" || c == nil {
		t.Fatalf("connect answered no session or cloud object: %v", out)
	}
	token, _ = c["token"].(string)
	return sid, token, c
}

// credentials asks for the command line's credentials as the AWS CLI would:
// the bearer and nothing else, no cookie.
func (f *cloudFixture) credentials(sid, bearer string) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cloud/"+sid+"/credentials", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.RemoteAddr = "198.51.100.7:5000"
	rr := httptest.NewRecorder()
	f.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

// console asks for a console sign-in as the portal does, signed in.
func (f *cloudFixture) console(sid string, cookie *http.Cookie, csrf string) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cloud/"+sid+"/console", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.RemoteAddr = "203.0.113.5:4000"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	f.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

// cast reads the session's recording.
func (f *cloudFixture) cast(t *testing.T) string {
	t.Helper()
	var text string
	_ = filepath.WalkDir(f.recDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".cast") {
			b, _ := os.ReadFile(p) // #nosec G304 -- the test's own temp dir
			text += string(b)
		}
		return nil
	})
	return text
}

// events lists the audit events of one action on the session.
func (f *cloudFixture) events(t *testing.T, action, sid string) []audit.Event {
	t.Helper()
	evs, _, err := f.auditLog.List(f.ctx, audit.Filter{Action: action, ObjectID: sid})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// gone waits for the gateway to let the session go.
func (f *cloudFixture) released(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for f.h.CloudSessions() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if f.h.CloudSessions() != 0 {
		t.Fatal("the session is still held")
	}
}

// moveClock makes the package clock movable for one test: set it before
// the session starts, move it through the skew.
func moveClock(t *testing.T) *atomic.Int64 {
	t.Helper()
	var skew atomic.Int64
	prev := cloudNow
	cloudNow = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	t.Cleanup(func() { cloudNow = prev })
	return &skew
}

// A cloud session (ADR 0050, 3): connect starts it and answers its handle,
// the row and the registry hold it, the command line takes credentials with
// the bearer alone, the console takes a sign-in form from the federation
// endpoint, and an administrator's terminate ends it with both end times on
// the record. The token lives in the answer and nowhere else.
func TestCloudSessionEndToEnd(t *testing.T) {
	f := newCloudFixture(t)
	sid, token, c := f.connectCloud(t)
	if !strings.HasPrefix(token, CloudTokenPrefix) || len(token) != len(CloudTokenPrefix)+43 {
		t.Fatalf("token %q", token)
	}
	url := testGateway + "/api/v1/cloud/" + sid + "/credentials"
	profile, _ := c["profile"].(string)
	for _, want := range []string{"[profile zanskar-prod-admin]\n", "credential_process = curl -sf -H \"Authorization: Bearer " + token + "\" " + url + "\n", "region = eu-west-1\n"} {
		if !strings.Contains(profile, want) {
			t.Errorf("profile lacks %q:\n%s", want, profile)
		}
	}
	if c["credentials_url"] != url || c["console"] != true || c["cli"] != true || c["account_id"] != "123456789012" || c["account_alias"] != "prod" || c["role_name"] != "Admin" || c["region"] != "eu-west-1" {
		t.Fatalf("cloud object: %v", c)
	}
	expires, err := time.Parse(time.RFC3339Nano, c["expires_at"].(string))
	if err != nil || expires.Before(time.Now().Add(59*time.Minute)) || expires.After(time.Now().Add(61*time.Minute)) {
		t.Fatalf("expires_at %v (%v): want the target's hour", c["expires_at"], err)
	}
	s, err := f.h.Sessions.Get(f.ctx, sid)
	if err != nil || s.EndedAt != nil || s.Protocol != "cloud" || s.TargetID != f.role.ID || s.CredentialID != "" || s.PolicyID != f.policy.ID {
		t.Fatalf("row: %+v %v", s, err)
	}
	l, ok := f.h.Registry.Get(sid)
	if !ok || l.Tap == nil || l.Cloud == nil || !l.Cloud.Console || !l.Cloud.CLI || l.Cloud.ConsoleUntil != nil || l.Protocol != "cloud" {
		t.Fatalf("registry: %v %+v", ok, l.Cloud)
	}
	// Only the hash is held.
	live, ok := f.h.clouds.lookup(sid)
	if !ok || live.hash != sha256.Sum256([]byte(token)) {
		t.Fatal("the session does not hold the token's hash")
	}
	evs := f.events(t, "session.start", sid)
	if len(evs) != 1 {
		t.Fatalf("start events: %d", len(evs))
	}
	var details map[string]any
	_ = json.Unmarshal(evs[0].Details, &details)
	if details["protocol"] != "cloud" || details["account"] != "123456789012" || details["role"] != testRoleARN || details["console"] != true || details["cli"] != true || details["ends_at"] == nil {
		t.Fatalf("start details: %v", details)
	}
	if strings.Contains(string(evs[0].Details), token) {
		t.Fatal("the token is in the audit log")
	}

	// The command line: a fifteen-minute mint as the person, with the
	// session's name, reused on the next call.
	rr, out := f.credentials(sid, token)
	if rr.Code != 200 || out["Version"] != float64(1) || out["AccessKeyId"] != "ASIA000000000A" || out["SecretAccessKey"] != "secret-A" || out["SessionToken"] != "token-A" {
		t.Fatalf("credentials: %d %v", rr.Code, out)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credentials cached")
	}
	exp, err := time.Parse(time.RFC3339, out["Expiration"].(string))
	if err != nil || exp.Before(time.Now().Add(14*time.Minute)) || exp.After(time.Now().Add(16*time.Minute)) {
		t.Fatalf("Expiration %v (%v): want fifteen minutes", out["Expiration"], err)
	}
	req := f.minter.last()
	if req.RoleARN != testRoleARN || req.ExternalID != f.role.CloudExternalID || req.SessionName != "zanskar-"+sid || req.SourceIdentity != "alice" || req.Duration != 15*time.Minute ||
		req.Tags["zanskar:user"] != "alice" || req.Tags["zanskar:session"] != sid {
		t.Fatalf("the mint: %+v", req)
	}
	if rr, out2 := f.credentials(sid, token); rr.Code != 200 || out2["AccessKeyId"] != out["AccessKeyId"] || f.minter.count() != 1 {
		t.Fatalf("second call: %d %v after %d mints, want the same credentials and no mint", rr.Code, out2, f.minter.count())
	}
	if evs := f.events(t, audit.SessionCloudCredentials, sid); len(evs) != 1 || evs[0].Outcome != audit.Success || !strings.Contains(string(evs[0].Details), `"until"`) || strings.Contains(string(evs[0].Details), "secret-A") {
		t.Fatalf("credentials events: %d %+v", len(evs), evs)
	}
	// A token that is not the session's learns nothing; no token, nothing.
	if rr, out := f.credentials(sid, token+"x"); rr.Code != 401 || out["code"] != "invalid_token" {
		t.Fatalf("wrong token: %d %v", rr.Code, out)
	}
	if rr, out := f.credentials(sid, ""); rr.Code != 401 || out["code"] != "invalid_token" {
		t.Fatalf("no token: %d %v", rr.Code, out)
	}
	if rr, out := f.credentials("nosuch", token); rr.Code != 401 || out["code"] != "invalid_token" {
		t.Fatalf("another session: %d %v", rr.Code, out)
	}

	// The console: a mint for the remaining time, exchanged at the
	// federation endpoint for the form the portal posts.
	rr, out = f.console(sid, f.cookie, f.csrf)
	if rr.Code != 200 || out["action"] != f.fed.srv.URL || out["duration_honoured"] != true {
		t.Fatalf("console: %d %v", rr.Code, out)
	}
	fields, _ := out["fields"].(map[string]any)
	if fields["Action"] != "login" || fields["Issuer"] != testGateway || fields["Destination"] != "https://eu-west-1.console.aws.amazon.com/" || !strings.HasPrefix(fields["SigninToken"].(string), "signin-token-") {
		t.Fatalf("form: %v", fields)
	}
	if f.fed.count() != 1 || f.fed.call(0)["Action"] != "getSigninToken" {
		t.Fatalf("federation calls: %d", f.fed.count())
	}
	asked := f.fed.call(0)["SessionDuration"]
	if asked != "3600" && asked != "3599" && asked != "3598" {
		t.Fatalf("SessionDuration %q, want the session's remaining hour", asked)
	}
	var sess map[string]string
	if err := json.Unmarshal([]byte(f.fed.call(0)["Session"]), &sess); err != nil || sess["sessionId"] != "ASIA000000000B" || sess["sessionKey"] != "secret-B" || sess["sessionToken"] != "token-B" {
		t.Fatalf("the federation got %q: %v", f.fed.call(0)["Session"], err)
	}
	if mint := f.minter.last(); mint.Duration < 59*time.Minute || mint.Duration > time.Hour || mint.SessionName != "zanskar-"+sid || mint.SourceIdentity != "alice" {
		t.Fatalf("the console's mint: %+v", mint)
	}
	until, err := time.Parse(time.RFC3339Nano, out["console_until"].(string))
	if err != nil || until.Before(time.Now().Add(58*time.Minute)) {
		t.Fatalf("console_until %v", out["console_until"])
	}
	if l, _ := f.h.Registry.Get(sid); l.Cloud == nil || l.Cloud.ConsoleUntil == nil || !l.Cloud.ConsoleUntil.Equal(until) {
		t.Fatalf("registry console_until: %+v", l.Cloud)
	}
	if evs := f.events(t, audit.SessionCloudConsole, sid); len(evs) != 1 || evs[0].Outcome != audit.Success || !strings.Contains(string(evs[0].Details), `"console_until"`) || strings.Contains(string(evs[0].Details), "signin-token") {
		t.Fatalf("console events: %d %+v", len(evs), evs)
	}

	// An administrator ends it: both endpoints refuse, and the recording
	// says what runs on.
	if !f.h.Registry.Terminate(sid) {
		t.Fatal("terminate")
	}
	if row, audited := f.endedWith(t, sid); row != session.EndAdminTerminated || audited != session.EndAdminTerminated {
		t.Fatalf("ended as %s / %s", row, audited)
	}
	f.released(t)
	if rr, out := f.credentials(sid, token); rr.Code != 410 || out["code"] != "session_ended" {
		t.Fatalf("credentials after the end: %d %v", rr.Code, out)
	}
	if rr, out := f.console(sid, f.cookie, f.csrf); rr.Code != 410 || out["code"] != "session_ended" {
		t.Fatalf("console after the end: %d %v", rr.Code, out)
	}
	s, _ = f.h.Sessions.Get(f.ctx, sid)
	rec, err := f.h.Sessions.GetRecording(f.ctx, s.RecordingID)
	if err != nil || rec.FinishedAt == nil || rec.SizeBytes == 0 {
		t.Fatalf("recording: %+v %v", rec, err)
	}
	cast := f.cast(t)
	for _, want := range []string{
		"session started as arn:aws:sts::123456789012:assumed-role/Admin/zanskar-" + sid,
		"command-line credentials issued until " + clock(exp),
		"console sign-in issued (runs until " + clock(until) + ")",
		"terminated; command-line credentials end by " + clock(exp) + ", console by " + clock(until),
	} {
		if !strings.Contains(cast, want) {
			t.Errorf("recording lacks %q:\n%s", want, cast)
		}
	}
	for _, secret := range []string{token, "secret-A", "secret-B", "token-A", "signin-token"} {
		if strings.Contains(cast, secret) {
			t.Errorf("the recording carries %q", secret)
		}
	}
}

// The command line's credentials are reused for twelve of their fifteen
// minutes, minted afresh within three of their end, and never told to last
// past the session's end (ADR 0050, 3).
func TestCloudCredentialsReuseRemintAndCap(t *testing.T) {
	f := newCloudFixture(t)
	skew := moveClock(t)
	sid, token, c := f.connectCloud(t)
	first, _ := f.credentials(sid, token)
	if first.Code != 200 || f.minter.count() != 1 {
		t.Fatalf("first: %d after %d mints", first.Code, f.minter.count())
	}
	// Eleven minutes on, four left: the same credentials, nothing said.
	skew.Store(int64(11 * time.Minute))
	rr, out := f.credentials(sid, token)
	if rr.Code != 200 || out["AccessKeyId"] != "ASIA000000000A" || f.minter.count() != 1 {
		t.Fatalf("inside the window: %d %v after %d mints", rr.Code, out, f.minter.count())
	}
	if evs := f.events(t, audit.SessionCloudCredentials, sid); len(evs) != 1 {
		t.Fatalf("a reuse was audited: %d events", len(evs))
	}
	// Twelve and a half minutes on, under three left: minted again, said.
	skew.Store(int64(12*time.Minute + 30*time.Second))
	rr, out = f.credentials(sid, token)
	if rr.Code != 200 || out["AccessKeyId"] != "ASIA000000000B" || f.minter.count() != 2 {
		t.Fatalf("near the end: %d %v after %d mints", rr.Code, out, f.minter.count())
	}
	if evs := f.events(t, audit.SessionCloudCredentials, sid); len(evs) != 2 {
		t.Fatalf("the re-mint was not audited: %d events", len(evs))
	}
	// Fifty-two minutes on, eight left: the credentials end by the
	// session's end as far as the client is told, however long STS gave.
	skew.Store(int64(52 * time.Minute))
	rr, out = f.credentials(sid, token)
	if rr.Code != 200 || f.minter.count() != 3 {
		t.Fatalf("capped: %d %v after %d mints", rr.Code, out, f.minter.count())
	}
	exp, _ := time.Parse(time.RFC3339, out["Expiration"].(string))
	ends, _ := time.Parse(time.RFC3339Nano, c["expires_at"].(string))
	if !exp.Equal(ends.Truncate(time.Second)) {
		t.Fatalf("Expiration %v, want the session's end %v", exp, ends)
	}
	if mint := f.minter.last(); mint.Duration != 15*time.Minute {
		t.Fatalf("STS was asked for %v, want its shortest", mint.Duration)
	}
	f.h.Registry.Terminate(sid)
	f.endedWith(t, sid)
	f.released(t)
	// Each line is a marker and an output event; the output events count.
	if n := strings.Count(f.cast(t), `"o","command-line credentials issued until`); n != 3 {
		t.Fatalf("%d issue lines, want one per mint (3)", n)
	}
}

// A session ends at its duration by itself, as max_duration, with no idle
// clock: the gateway sees no request stream. The target's hour is brought
// near by moving the clock back before the connect.
func TestCloudSessionEndsAtMaximum(t *testing.T) {
	f := newCloudFixture(t)
	skew := moveClock(t)
	skew.Store(-int64(time.Hour - 300*time.Millisecond))
	sid, _, _ := f.connectCloud(t)
	row, audited := f.endedWith(t, sid)
	if row != session.EndMaxDuration || audited != session.EndMaxDuration {
		t.Fatalf("ended as %s / %s", row, audited)
	}
	evs := f.events(t, "session.end", sid)
	if len(evs) != 1 || !strings.Contains(string(evs[0].Details), "the session's maximum of 1h0m0s") {
		t.Fatalf("end details: %s", evs[0].Details)
	}
	f.released(t)
	if _, has := f.connect(t, map[string]any{"target_id": f.role.ID, "protocol": "cloud"}); has["idle_seconds"] != nil {
		t.Fatal("a cloud session has an idle time")
	}
}

// The grant's maximum, where shorter than the target's, bounds the session.
func TestCloudSessionTakesTheGrantsMaximum(t *testing.T) {
	f := newCloudFixture(t)
	most := 20
	f.policy.Grants[0].MaxSessionMinutes = &most
	if err := f.h.Policies.Update(f.ctx, f.policy); err != nil {
		t.Fatal(err)
	}
	_, _, c := f.connectCloud(t)
	expires, _ := time.Parse(time.RFC3339Nano, c["expires_at"].(string))
	if expires.Before(time.Now().Add(19*time.Minute)) || expires.After(time.Now().Add(21*time.Minute)) {
		t.Fatalf("expires_at %v, want the grant's twenty minutes", expires)
	}
}

// The grant's switches (ADR 0050, 2): with the command line off no token is
// handed out and the credentials route refuses even the right one; with the
// console off the sign-in is refused. A change of either while the session
// runs ends it (policy_revoked); a change that keeps both does not.
func TestCloudSwitches(t *testing.T) {
	f := newCloudFixture(t)
	f.switches(t, true, false)
	sid, token, c := f.connectCloud(t)
	if c["cli"] != false || c["console"] != true || token != "" || c["credentials_url"] != "" || c["profile"] != "" {
		t.Fatalf("command line off: %v", c)
	}
	for _, k := range []string{"token", "credentials_url", "profile"} {
		if _, has := c[k]; !has {
			t.Errorf("the answer lacks %q, which the portal's type has always", k)
		}
	}
	// Were the token known all the same, the route still refuses.
	live, _ := f.h.clouds.lookup(sid)
	known := CloudTokenPrefix + strings.Repeat("k", 43)
	live.mu.Lock()
	live.hash = sha256.Sum256([]byte(known))
	live.mu.Unlock()
	if rr, out := f.credentials(sid, known); rr.Code != 403 || out["code"] != "cli_off" {
		t.Fatalf("cli off: %d %v", rr.Code, out)
	}
	if rr, _ := f.console(sid, f.cookie, f.csrf); rr.Code != 200 {
		t.Fatalf("the console stays open: %d", rr.Code)
	}
	// Opening the command line changes the terms: the session ends, and the
	// person connects again under them.
	f.switches(t, true, true)
	if n := f.h.Recheck(f.ctx, []string{f.alice.ID}); n != 1 {
		t.Fatalf("re-check ended %d sessions, want 1", n)
	}
	f.revoked(t, sid)
	f.released(t)

	f.switches(t, false, true)
	sid, token, c = f.connectCloud(t)
	if c["console"] != false || c["cli"] != true || token == "" {
		t.Fatalf("console off: %v", c)
	}
	if rr, out := f.console(sid, f.cookie, f.csrf); rr.Code != 403 || out["code"] != "console_off" {
		t.Fatalf("console off: %d %v", rr.Code, out)
	}
	if rr, _ := f.credentials(sid, token); rr.Code != 200 {
		t.Fatalf("the command line stays open: %d", rr.Code)
	}
	// A change that keeps the doors as they are leaves the session running.
	f.policy.Description = "renamed nothing"
	if err := f.h.Policies.Update(f.ctx, f.policy); err != nil {
		t.Fatal(err)
	}
	if n := f.h.Recheck(f.ctx, []string{f.alice.ID}); n != 0 {
		t.Fatalf("re-check ended %d sessions, want none", n)
	}
	f.stillLive(t, sid)
	// Shutting the command line a session uses ends it.
	f.switches(t, true, false)
	if n := f.h.Recheck(f.ctx, []string{f.alice.ID}); n != 1 {
		t.Fatalf("re-check ended %d sessions, want 1", n)
	}
	f.revoked(t, sid)
}

// The console sign-in's refusals: AWS declining the duration falls back to
// the credentials' own length and says so; another person's session, a
// visitor without a sign-in, a federation endpoint down and STS refusing
// each answer their own code, and nothing of them reaches the recording as
// a success.
func TestCloudConsoleFallbackAndRefusals(t *testing.T) {
	f := newCloudFixture(t)
	sid, _, _ := f.connectCloud(t)
	f.fed.refuseDuration = true
	rr, out := f.console(sid, f.cookie, f.csrf)
	if rr.Code != 200 || out["duration_honoured"] != false || f.fed.count() != 2 || f.fed.call(0)["SessionDuration"] == "" || f.fed.call(1)["SessionDuration"] != "" {
		t.Fatalf("fallback: %d %v after calls %v", rr.Code, out, f.fed.calls)
	}
	until, _ := time.Parse(time.RFC3339Nano, out["console_until"].(string))
	if until.Before(time.Now().Add(58 * time.Minute)) {
		t.Fatalf("console_until %v is not the credentials' end", until)
	}
	f.fed.refuseDuration = false

	// Another person, signed in, does not reach alice's session.
	bob, bobCSRF := f.signIn(t, "bob")
	if rr, out := f.console(sid, bob, bobCSRF); rr.Code != 404 || out["code"] != "not_found" {
		t.Fatalf("bob on alice's session: %d %v", rr.Code, out)
	}
	if rr, _ := f.console(sid, nil, ""); rr.Code != 401 {
		t.Fatalf("no sign-in: %d", rr.Code)
	}
	if rr, out := f.console("nosuch", f.cookie, f.csrf); rr.Code != 404 || out["code"] != "not_found" {
		t.Fatalf("no such session: %d %v", rr.Code, out)
	}
	// The endpoint down.
	f.fed.mu.Lock()
	f.fed.status = http.StatusInternalServerError
	f.fed.mu.Unlock()
	if rr, out := f.console(sid, f.cookie, f.csrf); rr.Code != 502 || out["code"] != "console_failed" {
		t.Fatalf("endpoint down: %d %v", rr.Code, out)
	}
	f.fed.mu.Lock()
	f.fed.status = 0
	f.fed.mu.Unlock()
	// STS refusing the mint.
	f.minter.fail(errors.Join(cloud.ErrMintRefused, errors.New("AccessDenied")))
	if rr, out := f.console(sid, f.cookie, f.csrf); rr.Code != 502 || out["code"] != "mint_failed" || !strings.Contains(out["message"].(string), "trust policy may have changed") {
		t.Fatalf("mint refused: %d %v", rr.Code, out)
	}
	_, token, _ := f.connectCloud(t) // a second session of alice's, for the command line's refusal
	sid2 := ""
	for _, l := range f.h.Registry.List() {
		if l.SessionID != sid {
			sid2 = l.SessionID
		}
	}
	if rr, out := f.credentials(sid2, token); rr.Code != 502 || out["code"] != "mint_failed" {
		t.Fatalf("credentials with STS refusing: %d %v", rr.Code, out)
	}
	f.minter.fail(nil)
	evs := f.events(t, audit.SessionCloudConsole, sid)
	failures := 0
	for _, ev := range evs {
		if ev.Outcome == audit.Failure {
			failures++
		}
	}
	if failures != 2 {
		t.Fatalf("console failures audited: %d of %d, want 2", failures, len(evs))
	}
	if evs := f.events(t, audit.SessionCloudCredentials, sid2); len(evs) != 1 || evs[0].Outcome != audit.Failure {
		t.Fatalf("credentials failure audited: %+v", evs)
	}
	f.stillLive(t, sid)
	f.h.Registry.Terminate(sid)
	f.h.Registry.Terminate(sid2)
	f.endedWith(t, sid)
	f.endedWith(t, sid2)
	f.released(t)
	cast := f.cast(t)
	for _, want := range []string{"console sign-in refused: AWS's sign-in endpoint refused the exchange", "console sign-in refused: the role refused the gateway", "command-line credentials refused: the role refused the gateway"} {
		if !strings.Contains(cast, want) {
			t.Errorf("recording lacks %q:\n%s", want, cast)
		}
	}
}

// The source identity is the username where STS takes it as it is (an
// email-form username does), and the mint carries it on every call the
// person makes; a target edit that ends the role's sessions ends this one.
func TestCloudSessionAsAnotherPerson(t *testing.T) {
	f := newCloudFixture(t)
	bob, bobCSRF := f.signIn(t, "bob.o-neil@example.com")
	u, err := f.users.GetByUsername(f.ctx, "bob.o-neil@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.groups.AddMember(f.ctx, f.opsID, u.ID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.h.Registry.TerminateUser(u.ID) })
	body, _ := json.Marshal(map[string]any{"target_id": f.role.ID, "protocol": "cloud"})
	rr := f.do("POST", "/api/v1/connect", "application/json", strings.NewReader(string(body)), bob, bobCSRF)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != 200 {
		t.Fatalf("bob connects: %d %v", rr.Code, out)
	}
	sid := out["session_id"].(string)
	token := out["cloud"].(map[string]any)["token"].(string)
	if rr, _ := f.credentials(sid, token); rr.Code != 200 {
		t.Fatalf("credentials: %d", rr.Code)
	}
	if mint := f.minter.last(); mint.SourceIdentity != "bob.o-neil@example.com" || mint.Tags["zanskar:user"] != "bob.o-neil@example.com" || mint.SessionName != "zanskar-"+sid {
		t.Fatalf("the mint: %+v", mint)
	}
	// Alice's cookie does not open bob's console.
	if rr, out := f.console(sid, f.cookie, f.csrf); rr.Code != 404 || out["code"] != "not_found" {
		t.Fatalf("alice on bob's session: %d %v", rr.Code, out)
	}
	// The administrator edits the role's account, role or ExternalId: the
	// target handler calls this, and the session ends.
	if n := f.h.TargetDisabled(f.role.ID); n != 1 {
		t.Fatalf("target edit ended %d sessions", n)
	}
	if row, _ := f.endedWith(t, sid); row != session.EndAdminTerminated {
		t.Fatalf("ended as %s", row)
	}
	if rr, out := f.credentials(sid, token); rr.Code != 410 || out["code"] != "session_ended" {
		t.Fatalf("after the edit: %d %v", rr.Code, out)
	}
}

// Without a public address nothing a session hands out would work: the
// protocol is refused with the reason, and the portal is told before a click.
func TestCloudSessionNeedsPublicURL(t *testing.T) {
	f := newCloudFixture(t)
	f.h.PublicURL = ""
	code, out := f.connect(t, map[string]any{"target_id": f.role.ID, "protocol": "cloud"})
	if code != http.StatusNotImplemented || out["code"] != "protocol_unavailable" || !strings.Contains(out["message"].(string), "ZANSKAR_PUBLIC_URL") {
		t.Fatalf("%d %v", code, out)
	}
	if ev := f.lastConnectEvent(t); ev.Outcome != audit.Failure {
		t.Fatalf("connect event: %+v", ev)
	}
	items := f.myCloudItems(t)
	if len(items) != 1 || items[0]["unavailable"] == nil || !strings.Contains(items[0]["unavailable"].(string), "ZANSKAR_PUBLIC_URL") {
		t.Fatalf("the portal is not told: %v", items)
	}
}

// myCloudItems lists the cloud roles among alice's reachable targets, as
// raw JSON objects; the fixture's hosts are left out.
func (f *cloudFixture) myCloudItems(t *testing.T) []map[string]any {
	t.Helper()
	rr := f.do("GET", "/api/v1/me/targets", "", nil, f.cookie, f.csrf)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rr.Code, rr.Body)
	}
	var page struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, it := range page.Items {
		if it["kind"] == "cloud" {
			out = append(out, it)
		}
	}
	return out
}

// The portal's list (ADR 0050): a role is kind cloud, reached over cloud
// alone, with a nested cloud object naming the account, the role, the region
// and which doors the caller's grants open, the strictest across them; no
// flat fields, no platform, nothing of the ARN.
func TestMyTargetsCloud(t *testing.T) {
	f := newCloudFixture(t)
	items := f.myCloudItems(t)
	if len(items) != 1 || items[0]["id"] != f.role.ID {
		t.Fatalf("items: %v", items)
	}
	it := items[0]
	c, _ := it["cloud"].(map[string]any)
	if c["account_id"] != "123456789012" || c["account_alias"] != "prod" || c["role_name"] != "Admin" || c["region"] != "eu-west-1" || c["console"] != true || c["cli"] != true {
		t.Fatalf("cloud object: %v", c)
	}
	if allowed, _ := it["allowed_protocols"].([]any); len(allowed) != 1 || allowed[0] != "cloud" || it["requires_approval"] != nil || it["unavailable"] != nil {
		t.Fatalf("protocols: %v", it)
	}
	for _, flat := range []string{"cloud_account", "cloud_account_id", "cloud_role", "cloud_region", "platform", "private_ip"} {
		if _, has := it[flat]; has {
			t.Errorf("the item carries %q", flat)
		}
	}
	if b, _ := json.Marshal(it); strings.Contains(string(b), testRoleARN) {
		t.Fatal("the ARN reached the portal")
	}
	// A second policy shutting the console: the strictest holds.
	shut := false
	g := policytest.Named(protocol.KindCloud, []string{f.role.ID}, "cloud")
	g.CloudConsole = &shut
	p2 := policytest.Policy("aws-prod-cli-only", []policy.Subject{policytest.Group(f.opsID)}, g)
	if err := f.h.Policies.Create(f.ctx, p2); err != nil {
		t.Fatal(err)
	}
	if c := f.myCloudItems(t)[0]["cloud"].(map[string]any); c["console"] != false || c["cli"] != true {
		t.Fatalf("two grants: %v", c)
	}
	// Both approval-gated: the portal offers Request.
	f.policy.Grants[0].Access = policy.AccessApproval
	p2.Grants[0].Access = policy.AccessApproval
	for _, p := range []*policy.Policy{f.policy, p2} {
		if err := f.h.Policies.Update(f.ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if it := f.myCloudItems(t)[0]; it["requires_approval"] == nil || it["requires_approval"].([]any)[0] != "cloud" {
		t.Fatalf("approval-gated: %v", it)
	}
	// A disabled role is not listed.
	f.role.Status = target.StatusDisabled
	if err := f.h.Targets.Update(f.ctx, f.role); err != nil {
		t.Fatal(err)
	}
	if items := f.myCloudItems(t); len(items) != 0 {
		t.Fatalf("a disabled role is listed: %v", items)
	}
}

// A role's session as the sweep and the sessions list see it: the row says
// cloud, the registry carries the terms, and a terminate through the
// registry's cause reads policy_revoked where a grant was withdrawn.
func TestCloudSessionGrantRevoked(t *testing.T) {
	f := newCloudFixture(t)
	sid, _, _ := f.connectCloud(t)
	if n := f.h.GrantRevoked(f.ctx, f.alice.ID, f.role.ID, "", "cloud"); n != 0 {
		t.Fatalf("a standing policy still admits: ended %d", n)
	}
	f.stillLive(t, sid)
	f.policy.Enabled = false
	if err := f.h.Policies.Update(f.ctx, f.policy); err != nil {
		t.Fatal(err)
	}
	if n := f.h.Recheck(f.ctx, []string{f.alice.ID}); n != 1 {
		t.Fatalf("re-check ended %d", n)
	}
	f.revoked(t, sid)
}
