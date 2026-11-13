// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/kubegw"
	"github.com/albatroxxx/zanskar/internal/gateway/kubegw/kubetest"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/policy/policytest"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/target"
)

const gatewayPEM = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"

// kubeFixture is the connect fixture with a cluster enrolled behind a fake
// API server, a service-account token in the vault, and a policy granting
// ops the prod namespace on it.
type kubeFixture struct {
	*connectFixture
	api     *kubetest.API
	cluster *target.Target
	policy  *policy.Policy
	recDir  string
}

func newKubeFixture(t *testing.T) *kubeFixture {
	t.Helper()
	f := newConnectFixture(t)
	dir := t.TempDir()
	f.h.Registry = gateway.NewRegistry()
	f.h.Storage = &recording.LocalStorage{Dir: dir}
	f.h.Kube = kubegw.NewSessions()
	f.h.PublicURL = "https://gw.example"
	f.h.Groups = f.groups
	f.h.GatewayCert = func() (string, bool) { return gatewayPEM, true }
	api := &kubetest.API{Token: "sa-token", Version: "v1.31.0"}
	apiServer, ca := kubetest.Start(t, api)
	cred := &credential.Credential{Name: "sa", Type: credential.TypeKubeToken, Mode: credential.ModeVaulted}
	if err := f.h.Vault.Create(f.ctx, cred, &credential.Secret{Password: "sa-token"}, f.alice.ID); err != nil {
		t.Fatal(err)
	}
	tg := &target.Target{Name: "Prod Cluster", OSFamily: target.Linux, KubeAPIServer: apiServer, KubeCA: ca,
		Tags: map[string]string{"env": "k8s"}, Credentials: map[target.Protocol]string{target.Kube: cred.ID}}
	if err := f.h.Targets.Create(f.ctx, tg); err != nil {
		t.Fatal(err)
	}
	g := policytest.Named(protocol.KindKubernetes, []string{tg.ID}, "kube")
	g.Namespaces = []string{"prod"}
	p := policytest.Policy("k8s", []policy.Subject{policytest.Group(f.opsID)}, g)
	if err := f.h.Policies.Create(f.ctx, p); err != nil {
		t.Fatal(err)
	}
	return &kubeFixture{connectFixture: f, api: api, cluster: tg, policy: p, recDir: dir}
}

// connectKube starts a kube session and returns its id and token.
func (f *kubeFixture) connectKube(t *testing.T) (sid, token string, out map[string]any) {
	t.Helper()
	code, out := f.connect(t, map[string]any{"target_id": f.cluster.ID, "protocol": "kube"})
	if code != http.StatusOK {
		t.Fatalf("connect: %d %v", code, out)
	}
	sid, _ = out["session_id"].(string)
	kc, _ := out["kubeconfig"].(string)
	for _, l := range strings.Split(kc, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "token: "); ok {
			token = v
		}
	}
	if sid == "" || token == "" {
		t.Fatalf("connect answered no session or token: %v", out)
	}
	return sid, token, out
}

// kubectl sends one request as kubectl would, with the session token.
func (f *kubeFixture) kubectl(sid, token, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/k8s/"+sid+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.RemoteAddr = "198.51.100.7:5000"
	rr := httptest.NewRecorder()
	f.srv.ServeHTTP(rr, req)
	return rr
}

// cast reads the session's recording.
func (f *kubeFixture) cast(t *testing.T) string {
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

// A kube session (ADR 0045, 3): connect answers a kubeconfig at once, the
// session is live and watched, requests go to the cluster as the person
// within the scope, and an administrator's terminate ends it, token and all.
func TestKubeSessionEndToEnd(t *testing.T) {
	f := newKubeFixture(t)
	sid, token, out := f.connectKube(t)
	kc := out["kubeconfig"].(string)
	for _, want := range []string{"server: https://gw.example/k8s/" + sid + "\n", "certificate-authority-data: ", "token: zk8s_", "current-context: zanskar-prod-cluster\n"} {
		if !strings.Contains(kc, want) {
			t.Errorf("kubeconfig lacks %q:\n%s", want, kc)
		}
	}
	if _, has := out["ticket"]; has {
		t.Error("a kube session has no ticket")
	}
	if out["idle_seconds"] != float64(900) || out["expires_at"] != nil {
		t.Errorf("terms: idle %v expires %v", out["idle_seconds"], out["expires_at"])
	}
	s, err := f.h.Sessions.Get(f.ctx, sid)
	if err != nil || s.EndedAt != nil || s.Protocol != "kube" || s.TargetID != f.cluster.ID {
		t.Fatalf("row: %+v %v", s, err)
	}
	l, ok := f.h.Registry.Get(sid)
	if !ok || l.Tap == nil || l.Kube == nil || strings.Join(l.Kube.Namespaces, ",") != "prod" || strings.Join(l.Kube.Groups, ",") != "ops" || l.Kube.ClusterScope {
		t.Fatalf("registry: %v %+v", ok, l.Kube)
	}
	evs, _, err := f.auditLog.List(f.ctx, audit.Filter{Action: "session.start", ObjectID: sid})
	if err != nil || len(evs) != 1 {
		t.Fatalf("start event: %v %d", err, len(evs))
	}
	var details map[string]any
	_ = json.Unmarshal(evs[0].Details, &details)
	if ns, _ := details["namespaces"].([]any); len(ns) != 1 || ns[0] != "prod" || details["acts_as"] != "person" || details["protocol"] != "kube" {
		t.Fatalf("start details: %v", details)
	}

	// Through the gateway as the person, within the scope.
	live, _, unsubscribe := l.Tap.Subscribe()
	defer unsubscribe()
	if rr := f.kubectl(sid, token, "/api/v1/namespaces/prod/pods"); rr.Code != 200 {
		t.Fatalf("pods: %d %s", rr.Code, rr.Body.String())
	}
	h := f.api.Last().Header
	if h.Get("Authorization") != "Bearer sa-token" || h.Get("Impersonate-User") != "alice" || strings.Join(h.Values("Impersonate-Group"), ",") != "system:authenticated,zanskar:ops" {
		t.Fatalf("the cluster saw %v", h)
	}
	if rr := f.kubectl(sid, token, "/api/v1/nodes"); rr.Code != 403 || !strings.Contains(rr.Body.String(), `"reason":"Forbidden"`) {
		t.Fatalf("nodes: %d %s", rr.Code, rr.Body.String())
	}
	if rr := f.kubectl(sid, token+"x", "/api/v1/namespaces/prod/pods"); rr.Code != 401 {
		t.Fatalf("wrong token: %d", rr.Code)
	}
	if rr := f.kubectl(sid, "", "/api/v1/namespaces/prod/pods"); rr.Code != 401 {
		t.Fatalf("no token: %d", rr.Code)
	}
	if rr := f.kubectl("nosuch", token, "/api/v1/namespaces/prod/pods"); rr.Code != 401 {
		t.Fatalf("another session: %d", rr.Code)
	}
	// A watcher sees the requests as they happen.
	select {
	case b := <-live:
		if !strings.Contains(string(b), "list pods -n prod → 200") {
			t.Fatalf("tap carried %q", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the tap carried nothing")
	}

	// An administrator ends it: the token is refused and the recording closed.
	if !f.h.Registry.Terminate(sid) {
		t.Fatal("terminate")
	}
	if row, audited := f.endedWith(t, sid); row != "admin_terminated" || audited != "admin_terminated" {
		t.Fatalf("ended as %s / %s", row, audited)
	}
	if rr := f.kubectl(sid, token, "/api/v1/namespaces/prod/pods"); rr.Code != 401 {
		t.Fatalf("after the end: %d", rr.Code)
	}
	if f.h.Kube.Len() != 0 {
		t.Fatal("the session is still held")
	}
	s, _ = f.h.Sessions.Get(f.ctx, sid)
	rec, err := f.h.Sessions.GetRecording(f.ctx, s.RecordingID)
	if err != nil || rec.FinishedAt == nil || rec.SizeBytes == 0 {
		t.Fatalf("recording: %+v %v", rec, err)
	}
	cast := f.cast(t)
	for _, want := range []string{`"m","list pods -n prod → 200"`, `"o","list pods -n prod → 200\r\n"`, "list nodes → 403 (gateway: outside the access)"} {
		if !strings.Contains(cast, want) {
			t.Errorf("recording lacks %q:\n%s", want, cast)
		}
	}
}

// With kube_impersonate off the session is the credential itself, and the
// audit says so.
func TestKubeSessionSharedIdentity(t *testing.T) {
	f := newKubeFixture(t)
	off := false
	f.cluster.KubeImpersonate = &off
	if err := f.h.Targets.Update(f.ctx, f.cluster); err != nil {
		t.Fatal(err)
	}
	sid, token, _ := f.connectKube(t)
	if rr := f.kubectl(sid, token, "/api/v1/namespaces/prod/pods"); rr.Code != 200 {
		t.Fatalf("pods: %d", rr.Code)
	}
	if h := f.api.Last().Header; h.Get("Impersonate-User") != "" || len(h.Values("Impersonate-Group")) != 0 {
		t.Fatalf("shared identity impersonated: %v", h)
	}
	evs, _, _ := f.auditLog.List(f.ctx, audit.Filter{Action: "session.start", ObjectID: sid})
	var details map[string]any
	_ = json.Unmarshal(evs[0].Details, &details)
	if details["acts_as"] != "shared identity" {
		t.Fatalf("start details: %v", details)
	}
}

// Without a public address there is nothing to put in a kubeconfig: the
// protocol is off, with the reason.
func TestKubeSessionNeedsPublicURL(t *testing.T) {
	f := newKubeFixture(t)
	f.h.PublicURL = ""
	code, out := f.connect(t, map[string]any{"target_id": f.cluster.ID, "protocol": "kube"})
	if code != http.StatusNotImplemented || out["code"] != "protocol_unavailable" || !strings.Contains(out["message"].(string), "ZANSKAR_PUBLIC_URL") {
		t.Fatalf("%d %v", code, out)
	}
	if ev := f.lastConnectEvent(t); ev.Outcome != audit.Failure {
		t.Fatalf("connect event: %+v", ev)
	}
	// A pod shell is phase 2.
	if code, out := f.connect(t, map[string]any{"target_id": f.cluster.ID, "protocol": "pod"}); code != http.StatusNotImplemented {
		t.Fatalf("pod: %d %v", code, out)
	}
}

// Without a request for the policy's idle time the session ends by itself.
func TestKubeSessionIdlesOut(t *testing.T) {
	f := newKubeFixture(t)
	// The run reads the clock on every tick, so the clock is set before the
	// session starts and moved through an atomic.
	var skew atomic.Int64
	tick, now := kubeTick, kubeNow
	kubeTick = 20 * time.Millisecond
	kubeNow = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	t.Cleanup(func() { kubeTick, kubeNow = tick, now })
	sid, token, _ := f.connectKube(t)
	if rr := f.kubectl(sid, token, "/api/v1/namespaces/prod/pods"); rr.Code != 200 {
		t.Fatalf("pods: %d", rr.Code)
	}
	time.Sleep(60 * time.Millisecond)
	f.stillLive(t, sid)
	// Sixteen minutes pass with no request (the grant's idle time is fifteen).
	skew.Store(int64(16 * time.Minute))
	if row, _ := f.endedWith(t, sid); row != "idle_timeout" {
		t.Fatalf("ended as %s", row)
	}
	if rr := f.kubectl(sid, token, "/api/v1/namespaces/prod/pods"); rr.Code != 401 {
		t.Fatalf("after idling out: %d", rr.Code)
	}
	s, _ := f.h.Sessions.Get(f.ctx, sid)
	if !strings.Contains(s.EndDetail, "15m0s without a request") {
		t.Fatalf("detail %q", s.EndDetail)
	}
}

// A grant whose scope changes ends the sessions running on it; one that does
// not keeps them (ADR 0045, with the clipboard precedent).
func TestKubeSessionEndsWhenTheScopeChanges(t *testing.T) {
	f := newKubeFixture(t)
	sid, _, _ := f.connectKube(t)
	if n := f.h.Recheck(f.ctx, []string{f.alice.ID}); n != 0 {
		t.Fatalf("an unchanged policy ended %d sessions", n)
	}
	f.stillLive(t, sid)
	f.policy.Grants[0].Namespaces = []string{"prod", "staging"}
	if err := f.h.Policies.Update(f.ctx, f.policy); err != nil {
		t.Fatal(err)
	}
	if n := f.h.Recheck(f.ctx, []string{f.alice.ID}); n != 1 {
		t.Fatalf("a widened scope ended %d sessions, want 1", n)
	}
	if row, _ := f.endedWith(t, sid); row != "policy_revoked" {
		t.Fatalf("ended as %s", row)
	}
}
