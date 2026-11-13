// SPDX-License-Identifier: Apache-2.0

package kubegw

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/gateway/kubegw/kubetest"
)

// lines collects what a session records.
type lines struct {
	mu sync.Mutex
	l  []string
}

func (l *lines) add(s string) {
	l.mu.Lock()
	l.l = append(l.l, s)
	l.mu.Unlock()
}

func (l *lines) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.l...)
}

func newSession(t *testing.T, f *kubetest.API, id Identity, scope Scope) (*Session, string, *lines) {
	t.Helper()
	api, ca := kubetest.Start(t, f)
	rec := &lines{}
	s, tok, err := NewSession(Options{SessionID: "s1", Endpoint: Endpoint{APIServer: api, CA: ca}, Credential: Credential{Token: f.Token},
		Identity: id, Scope: scope, Record: rec.add})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, tok, rec
}

// serve mounts the session as the gateway does, under /k8s/{id}/.
func serve(t *testing.T, s *Session) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.StripPrefix("/k8s/"+s.ID, s))
	t.Cleanup(srv.Close)
	return srv
}

// request is one GET with the session token, as kubectl would send it.
func request(t *testing.T, srv *httptest.Server, tok, path string, hdr map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/k8s/s1"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return req
}

// fetch sends the request and returns the status and the whole body.
func fetch(t *testing.T, srv *httptest.Server, tok, path string, hdr map[string]string) (int, []byte) {
	t.Helper()
	res, err := srv.Client().Do(request(t, srv, tok, path, hdr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}

// Every request goes to the cluster as the person, with Zanskar's credential
// in place of whatever the person sent as identity (ADR 0045, 2 and 3).
func TestProxyForwardsAsThePerson(t *testing.T) {
	f := &kubetest.API{Token: "sa-token"}
	s, tok, rec := newSession(t, f, Identity{User: "alice", Groups: []string{"ops", "data"}}, Scope{Namespaces: []string{"prod"}})
	srv := serve(t, s)
	code, b := fetch(t, srv, tok, "/api/v1/namespaces/prod/pods?limit=5", map[string]string{
		"Impersonate-User": "root", "Impersonate-Group": "system:masters", "Impersonate-Extra-Scopes": "everything", "Impersonate-Uid": "0",
		"X-Remote-User": "root", "X-Forwarded-For": "1.2.3.4", "Cookie": "zanskar=abc", "X-Real-Ip": "1.2.3.4", "Accept": "application/json",
	})
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	var body struct {
		Metadata struct{ Path string } `json:"metadata"`
	}
	_ = json.Unmarshal(b, &body)
	if body.Metadata.Path != "/api/v1/namespaces/prod/pods" {
		t.Fatalf("the cluster saw %q", body.Metadata.Path)
	}
	last := f.Last()
	if last.Proto != "HTTP/1.1" || last.Query != "limit=5" {
		t.Fatalf("proto %s query %q", last.Proto, last.Query)
	}
	h := last.Header
	if h.Get("Authorization") != "Bearer sa-token" {
		t.Fatalf("authorization %q", h.Get("Authorization"))
	}
	if h.Get("Impersonate-User") != "alice" || strings.Join(h.Values("Impersonate-Group"), ",") != "system:authenticated,zanskar:ops,zanskar:data" {
		t.Fatalf("impersonation: %v %v", h.Get("Impersonate-User"), h.Values("Impersonate-Group"))
	}
	for _, k := range []string{"Impersonate-Extra-Scopes", "Impersonate-Uid", "X-Remote-User", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Cookie", "X-Real-Ip"} {
		if v := h.Values(k); len(v) > 0 {
			t.Errorf("%s reached the cluster: %v", k, v)
		}
	}
	if h.Get("Accept") != "application/json" {
		t.Error("the person's own headers must pass")
	}
	if got := rec.all(); len(got) != 1 || got[0] != "list pods -n prod → 200" {
		t.Fatalf("recorded %q", got)
	}
	if time.Since(s.LastActive()) > time.Second {
		t.Fatal("a request must count as activity")
	}
}

// With kube_impersonate off the session is the credential itself.
func TestProxySharedIdentity(t *testing.T) {
	f := &kubetest.API{Token: "sa-token"}
	s, tok, _ := newSession(t, f, Identity{}, Scope{ClusterScope: true})
	srv := serve(t, s)
	if code, _ := fetch(t, srv, tok, "/api/v1/nodes", map[string]string{"Impersonate-User": "root"}); code != 200 {
		t.Fatalf("status %d", code)
	}
	if h := f.Last().Header; h.Get("Impersonate-User") != "" || len(h.Values("Impersonate-Group")) != 0 {
		t.Fatalf("shared identity must impersonate nobody: %v", h)
	}
}

// The gateway holds the line before the cluster: outside the scope nothing
// is forwarded, and the answer reads as the API's own refusal.
func TestProxyRefusals(t *testing.T) {
	f := &kubetest.API{Token: "sa-token"}
	s, tok, rec := newSession(t, f, Identity{User: "alice"}, Scope{Namespaces: []string{"prod"}})
	srv := serve(t, s)
	before := f.Count()
	code, b := fetch(t, srv, tok, "/api/v1/nodes", nil)
	var st struct {
		Kind, Status, Message, Reason string
		Code                          int
	}
	_ = json.Unmarshal(b, &st)
	if code != 403 || st.Kind != "Status" || st.Reason != "Forbidden" || st.Code != 403 || !strings.Contains(st.Message, "covers the namespaces prod only") {
		t.Fatalf("%d %+v", code, st)
	}
	if code, _ = fetch(t, srv, tok, "/metrics", nil); code != 404 {
		t.Fatalf("outside the API: %d", code)
	}
	if code, _ = fetch(t, srv, tok, "/api/v1/namespaces/kube-system/pods", nil); code != 403 {
		t.Fatalf("another namespace: %d", code)
	}
	if f.Count() != before {
		t.Fatal("a refused request reached the cluster")
	}
	if got := rec.all(); len(got) != 2 || got[0] != "list nodes → 403 (gateway: outside the access)" || got[1] != "list pods -n kube-system → 403 (gateway: outside the access)" {
		t.Fatalf("recorded %q", got)
	}
	// Discovery passes and is not recorded: kubectl asks for it a dozen
	// times before its first real request.
	for _, p := range []string{"/api", "/apis", "/api/v1", "/version"} {
		if code, _ = fetch(t, srv, tok, p, nil); code != 200 {
			t.Fatalf("%s: %d", p, code)
		}
	}
	if got := rec.all(); len(got) != 2 {
		t.Fatalf("discovery was recorded: %q", got)
	}
}

// The token opens its own session alone, while the session is open.
func TestSessionsTokens(t *testing.T) {
	f := &kubetest.API{Token: "sa-token"}
	s1, tok1, _ := newSession(t, f, Identity{User: "alice"}, Scope{})
	s2, tok2, _ := newSession(t, f, Identity{User: "bob"}, Scope{})
	s2.ID = "s2"
	ss := NewSessions()
	ss.Add(s1)
	ss.Add(s2)
	if got, ok := ss.Get("s1", tok1); !ok || got != s1 {
		t.Fatal("own token")
	}
	if _, ok := ss.Get("s1", tok2); ok {
		t.Fatal("another session's token opened a session")
	}
	if _, ok := ss.Get("s1", tok1+"x"); ok {
		t.Fatal("a wrong token opened a session")
	}
	if _, ok := ss.Get("s3", tok1); ok {
		t.Fatal("an unknown session opened")
	}
	if !strings.HasPrefix(tok1, TokenPrefix) || len(tok1) < 40 || tok1 == tok2 {
		t.Fatalf("token %q", tok1)
	}
	r := httptest.NewRequest(http.MethodGet, "/k8s/s1/api?token="+tok1, nil)
	if Bearer(r) != "" {
		t.Fatal("a token in the URL must not count")
	}
	r.Header.Set("Authorization", "Bearer "+tok1)
	if Bearer(r) != tok1 {
		t.Fatal("Bearer")
	}
	r.Header.Set("Authorization", "Bearer zapi_notours")
	if Bearer(r) != "" {
		t.Fatal("an API token is not a session token")
	}
	ss.Remove("s1")
	if _, ok := ss.Get("s1", tok1); ok || ss.Len() != 1 {
		t.Fatal("a removed session must refuse its token")
	}
	if s1.Authenticate(tok1) {
		t.Fatal("a closed session must refuse its token")
	}
	rr := httptest.NewRecorder()
	WriteUnauthorized(rr)
	if rr.Code != 401 || !strings.Contains(rr.Body.String(), `"reason":"Unauthorized"`) || rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("unauthorized: %d %s", rr.Code, rr.Body.String())
	}
}

// A watch streams as it comes and ends when the session does.
func TestProxyWatchStreamsAndEndsWithTheSession(t *testing.T) {
	f := &kubetest.API{Token: "sa-token", WatchEvents: 2}
	s, tok, rec := newSession(t, f, Identity{User: "alice"}, Scope{Namespaces: []string{"prod"}})
	srv := serve(t, s)
	res, err := srv.Client().Do(request(t, srv, tok, "/api/v1/namespaces/prod/pods?watch=true", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	rd := bufio.NewReader(res.Body)
	for i := range 2 {
		line, err := rd.ReadString('\n')
		if err != nil || !strings.Contains(line, "ADDED") {
			t.Fatalf("event %d: %q %v", i, line, err)
		}
	}
	// The cluster holds the stream; the session's end cuts it.
	done := make(chan error, 1)
	go func() {
		_, err := rd.ReadString('\n')
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	s.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the stream went on")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the stream did not end with the session")
	}
	if got := rec.all(); len(got) != 1 || got[0] != "watch pods -n prod → 200" {
		t.Fatalf("recorded %q", got)
	}
}

// An upgraded stream (exec) passes through, its bytes counted, and is closed
// with the session.
func TestProxyUpgradedStream(t *testing.T) {
	f := &kubetest.API{Token: "sa-token"}
	s, tok, rec := newSession(t, f, Identity{User: "alice"}, Scope{Namespaces: []string{"prod"}})
	srv := serve(t, s)
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(conn, "POST /k8s/s1/api/v1/namespaces/prod/pods/web-1/exec?command=sh HTTP/1.1\r\nHost: gw\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\nAuthorization: Bearer "+tok+"\r\n\r\n")
	rd := bufio.NewReader(conn)
	status, err := rd.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 101") {
		t.Fatalf("status %q %v", status, err)
	}
	for {
		l, err := rd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" {
			break
		}
	}
	if _, err := io.WriteString(conn, "hello"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(rd, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo %q %v", buf, err)
	}
	if s.Streams() != 1 {
		t.Fatalf("streams %d", s.Streams())
	}
	if h := f.Last().Header; h.Get("Impersonate-User") != "alice" || h.Get("Authorization") != "Bearer sa-token" {
		t.Fatalf("the stream's request must carry the identity too: %v", h)
	}
	s.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := rd.ReadByte(); err == nil {
		t.Fatal("the stream outlived the session")
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.Streams() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := rec.all()
	if len(got) != 2 || got[0] != "exec pods/web-1 -n prod → stream opened" || !strings.HasPrefix(got[1], "exec pods/web-1 -n prod → stream ended after ") || !strings.Contains(got[1], "5 B sent, 5 B received") {
		t.Fatalf("recorded %q", got)
	}
}

// Session.Watch ties the session to a context: when it ends, the token is
// refused.
func TestSessionWatch(t *testing.T) {
	f := &kubetest.API{Token: "sa-token"}
	s, tok, _ := newSession(t, f, Identity{User: "alice"}, Scope{})
	ctx, cancel := context.WithCancel(context.Background())
	s.Watch(ctx)
	if !s.Authenticate(tok) {
		t.Fatal("open")
	}
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for s.Authenticate(tok) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.Authenticate(tok) {
		t.Fatal("the session outlived its context")
	}
}

// The cluster being down is a 502 in the API's words, recorded.
func TestProxyClusterDown(t *testing.T) {
	f := &kubetest.API{Token: "sa-token"}
	api, ca := kubetest.Start(t, f)
	rec := &lines{}
	s, tok, err := NewSession(Options{SessionID: "s1", Endpoint: Endpoint{APIServer: "https://127.0.0.1:1", CA: ca}, Credential: Credential{Token: "sa-token"},
		Identity: Identity{User: "alice"}, Scope: Scope{ClusterScope: true}, Record: rec.add})
	if err != nil {
		t.Fatal(err)
	}
	_ = api
	srv := serve(t, s)
	code, _ := fetch(t, srv, tok, "/api/v1/nodes", nil)
	if code != 502 || !strings.Contains(rec.all()[0], "→ 502 (cluster unreachable)") {
		t.Fatalf("%d %q", code, rec.all())
	}
}

// A credential whose token is minted (an EKS role, ADR 0045 8) is asked for
// the bearer of each request; one it cannot mint is a 502 that names the
// gateway's credential, written to the recording, and nothing reaches the
// cluster.
func TestProxyBearerSource(t *testing.T) {
	f := &kubetest.API{Token: "k8s-aws-v1.(fake)"}
	api, ca := kubetest.Start(t, f)
	var fail bool
	var minted int
	bearer := func(context.Context) (string, error) {
		minted++
		if fail {
			return "", errors.New("AccessDenied: sts:AssumeRole")
		}
		return "k8s-aws-v1.(fake)", nil
	}
	rec := &lines{}
	s, tok, err := NewSession(Options{SessionID: "s1", Endpoint: Endpoint{APIServer: api, CA: ca}, Credential: Credential{Bearer: bearer},
		Identity: Identity{User: "alice"}, Scope: Scope{Namespaces: []string{"prod"}}, Record: rec.add})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	srv := serve(t, s)
	if code, _ := fetch(t, srv, tok, "/api/v1/namespaces/prod/pods", nil); code != 200 || minted != 1 {
		t.Fatalf("minted bearer: %d, %d mints", code, minted)
	}
	if f.Last().Header.Get("Authorization") != "Bearer k8s-aws-v1.(fake)" {
		t.Fatalf("the cluster saw %q", f.Last().Header.Get("Authorization"))
	}
	fail = true
	before := f.Count()
	code, body := fetch(t, srv, tok, "/api/v1/namespaces/prod/pods", nil)
	if code != 502 || !strings.Contains(string(body), "could not be minted") || f.Count() != before {
		t.Fatalf("mint failed: %d %s (%d requests reached the cluster)", code, body, f.Count()-before)
	}
	if all := rec.all(); !slices.ContainsFunc(all, func(l string) bool { return strings.Contains(l, "502 (token could not be minted)") }) {
		t.Fatalf("recording: %v", all)
	}
}

func TestKubeconfig(t *testing.T) {
	k := Kubeconfig(KubeconfigOptions{Name: "Prod Cluster (EU)", Server: "https://gw.example/k8s/s1", Token: "zk8s_abc", CAPEM: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"})
	for _, want := range []string{"name: zanskar-prod-cluster-eu\n", "server: https://gw.example/k8s/s1\n", "certificate-authority-data: ", "token: zk8s_abc\n", "current-context: zanskar-prod-cluster-eu\n"} {
		if !strings.Contains(k, want) {
			t.Errorf("kubeconfig lacks %q:\n%s", want, k)
		}
	}
	if k2 := Kubeconfig(KubeconfigOptions{Server: "https://gw/k8s/s2", Token: "t"}); strings.Contains(k2, "certificate-authority-data") || !strings.Contains(k2, "name: zanskar-cluster\n") {
		t.Errorf("without a CA or a name:\n%s", k2)
	}
}
