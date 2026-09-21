// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/asg"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/cloud"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/ticket"
	"github.com/albatroxxx/zanskar/internal/user"
)

type asgEnv struct {
	srv      http.Handler
	cookie   *http.Cookie
	csrf     string
	h        *Handler
	asgs     *asg.Repo
	sessions *session.Repo
	users    *user.Repo
	user     *user.User
	group    *asg.Group
}

func newASGEnv(t *testing.T) *asgEnv {
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
	kek, _ := crypto.NewLocalKEK(bytes.Repeat([]byte{3}, 32))
	ring, _ := keyring.Open(ctx, db, kek)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	u := &user.User{Username: "alice", DisplayName: "Alice", Roles: []user.Role{user.RoleUser}}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	groups := group.NewRepo(db)
	g := &group.Group{Name: "ops"}
	if err := groups.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := groups.AddMember(ctx, g.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	vault := credential.NewVault(db, ring)
	cred := &credential.Credential{Name: "eic", Type: credential.TypeEC2InstanceConnect, Mode: credential.ModeVaulted, Username: "ec2-user"}
	if err := vault.Create(ctx, cred, nil, u.ID); err != nil {
		t.Fatal(err)
	}
	asgs := asg.NewRepo(db)
	ag := &asg.Group{Name: "web", Region: "ap-south-1", ExternalName: "web-asg", RoleARN: "arn:aws:iam::123456789012:role/z", OSFamily: target.Linux,
		Tags: map[string]string{"env": "prod"}, Credentials: map[target.Protocol]string{target.SSH: cred.ID}}
	if err := asgs.Create(ctx, ag); err != nil {
		t.Fatal(err)
	}
	pol := &policy.Policy{Name: "ops-web", GroupID: g.ID, Enabled: true, Selector: policy.Selector{ASGs: []string{ag.ID}}, Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15}
	if err := policy.NewRepo(db).Create(ctx, pol); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{1}, 32), false)
	tok, sess, err := sessions.Create(ctx, u.ID, "203.0.113.5", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Targets: target.NewRepo(db), Policies: policy.NewRepo(db), Vault: vault, Sessions: session.NewRepo(db), Tickets: ticket.NewStore(),
		Audit: audit.NewLog(db), Log: log, ASGs: asgs, MFAEnrolled: func(context.Context, string) (bool, error) { return true, nil },
		Cloud: func(context.Context, *asg.Group) (cloud.Provider, error) { return cloud.NewFake(), nil }}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	return &asgEnv{srv: mw.Authenticate(mw.CSRF(mux)), cookie: &http.Cookie{Name: auth.CookieName, Value: tok}, csrf: sessions.CSRFToken(sess.ID),
		h: h, asgs: asgs, sessions: session.NewRepo(db), users: users, user: u, group: ag}
}

func (e *asgEnv) do(method, path string, body any) (int, map[string]any) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.RemoteAddr = "203.0.113.5:9"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.AddCookie(e.cookie)
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func TestASGTargetsInstancesConnectAndFailover(t *testing.T) {
	e := newASGEnv(t)
	ctx := context.Background()

	// Empty pool: the group is listed with zero healthy, connect refuses.
	code, out := e.do("GET", "/api/v1/me/targets", nil)
	items := out["items"].([]any)
	if code != 200 || len(items) != 1 || items[0].(map[string]any)["kind"] != "asg" || items[0].(map[string]any)["healthy_count"] != nil {
		t.Fatalf("targets: %d %v", code, out)
	}
	if code, out := e.do("POST", "/api/v1/connect", map[string]any{"asg_id": e.group.ID, "protocol": "ssh"}); code != 409 || out["code"] != "no_healthy_instances" {
		t.Fatalf("empty pool connect: %d %v", code, out)
	}

	// One healthy, pinned instance appears.
	launched := time.Now()
	in, _, err := e.asgs.UpsertInstance(ctx, &asg.Instance{GroupID: e.group.ID, InstanceID: "i-1", PrivateIP: "10.0.0.5", AvailabilityZone: "ap-south-1a",
		LifecycleState: "InService", ProbeHealth: "healthy", HostKeyFingerprint: "SHA256:abc", HostKeySource: "console", LaunchedAt: &launched})
	if err != nil {
		t.Fatal(err)
	}
	code, out = e.do("GET", "/api/v1/me/autoscaling-groups/"+e.group.ID+"/instances", nil)
	if code != 200 || len(out["items"].([]any)) != 1 || out["items"].([]any)[0].(map[string]any)["private_ip"] != nil {
		t.Fatalf("instances (must not expose ips): %d %v", code, out)
	}
	code, out = e.do("POST", "/api/v1/connect", map[string]any{"asg_id": e.group.ID, "protocol": "ssh"})
	if code != 200 || out["ticket"] == nil || out["asg_instance_id"] != in.ID || out["ws_path"] != "/ws/terminal" {
		t.Fatalf("connect newest: %d %v", code, out)
	}
	// Desktop protocols are not offered for groups in this release.
	if code, out := e.do("POST", "/api/v1/connect", map[string]any{"asg_instance_id": in.ID, "protocol": "rdp"}); code == 200 {
		t.Fatalf("rdp on asg must be refused: %d %v", code, out)
	}

	// Failover rules: not on a live healthy instance; allowed after target_lost.
	s := &session.Session{UserID: e.user.ID, ASGID: e.group.ID, ASGInstanceID: in.ID, Protocol: "ssh", ClientIP: "203.0.113.5"}
	if err := e.sessions.Start(ctx, s); err != nil {
		t.Fatal(err)
	}
	if code, out := e.do("POST", "/api/v1/sessions/"+s.ID+"/failover", map[string]any{}); code != 409 || out["code"] != "not_failoverable" {
		t.Fatalf("failover while healthy: %d %v", code, out)
	}
	if err := e.sessions.End(ctx, s.ID, session.EndTargetLost); err != nil {
		t.Fatal(err)
	}
	in2, _, err := e.asgs.UpsertInstance(ctx, &asg.Instance{GroupID: e.group.ID, InstanceID: "i-2", PrivateIP: "10.0.0.6", AvailabilityZone: "ap-south-1b",
		LifecycleState: "InService", ProbeHealth: "healthy", HostKeyFingerprint: "SHA256:def", HostKeySource: "tofu"})
	if err != nil {
		t.Fatal(err)
	}
	code, out = e.do("POST", "/api/v1/sessions/"+s.ID+"/failover", map[string]any{"asg_instance_id": in2.ID})
	if code != 200 || out["asg_instance_id"] != in2.ID || out["ticket"] == nil {
		t.Fatalf("failover: %d %v", code, out)
	}
	bob := &user.User{Username: "bob", DisplayName: "Bob", Roles: []user.Role{user.RoleUser}}
	if err := e.users.Create(ctx, bob); err != nil {
		t.Fatal(err)
	}
	other := &session.Session{UserID: bob.ID, ASGID: e.group.ID, ASGInstanceID: in.ID, Protocol: "ssh", ClientIP: "x"}
	if err := e.sessions.Start(ctx, other); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.do("POST", "/api/v1/sessions/"+other.ID+"/failover", map[string]any{}); code != 403 {
		t.Fatalf("foreign session failover: %d", code)
	}
	events, _, _ := e.h.Audit.List(ctx, audit.Filter{Action: "session.failover"})
	if len(events) != 1 || events[0].Outcome != audit.Success {
		t.Fatalf("audit: %v", events)
	}
}
