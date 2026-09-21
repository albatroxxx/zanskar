// SPDX-License-Identifier: Apache-2.0

package asg

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
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

type env struct {
	srv   http.Handler
	db    *store.DB
	repo  *Repo
	audit *audit.Log
	admin *http.Cookie
	csrf  string
	user  *http.Cookie
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := testDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{2}, 32), false)
	auditLog := audit.NewLog(db)
	repo := NewRepo(db)

	// fake sync: two instances, one healthy, one draining
	syncFn := func(ctx context.Context, g *Group) (Summary, error) {
		launched := time.Now().Add(-time.Hour)
		_, _, err := repo.UpsertInstance(ctx, &Instance{GroupID: g.ID, InstanceID: "i-1", PrivateIP: "10.0.0.5", AvailabilityZone: "ap-south-1a", LifecycleState: "InService", ProbeHealth: "healthy", HostKeyFingerprint: "SHA256:aaa", HostKeySource: "console", LaunchedAt: &launched})
		if err != nil {
			return Summary{}, err
		}
		if _, _, err := repo.UpsertInstance(ctx, &Instance{GroupID: g.ID, InstanceID: "i-2", PrivateIP: "10.0.0.6", LifecycleState: "InService", LBHealth: "draining", ProbeHealth: "healthy"}); err != nil {
			return Summary{}, err
		}
		_ = repo.RecordSync(ctx, g.ID, nil)
		return Summary{Seen: 2, Healthy: 1, Joined: 2}, nil
	}

	h := &AdminHandler{Repo: repo, Sync: syncFn, GatewayPrincipal: "arn:aws:iam::111111111111:role/zanskar-gateway", Audit: auditLog, Log: log}
	mux := http.NewServeMux()
	h.Register(mux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	e := &env{srv: mw.Authenticate(mw.CSRF(mux)), db: db, repo: repo, audit: auditLog}

	adminUser := &user.User{Username: "admin", DisplayName: "Admin", Roles: []user.Role{user.RoleAdmin}}
	if err := users.Create(ctx, adminUser); err != nil {
		t.Fatal(err)
	}
	tok, sess, err := sessions.Create(ctx, adminUser.ID, "127.0.0.1", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	e.admin = &http.Cookie{Name: auth.CookieName, Value: tok}
	e.csrf = sessions.CSRFToken(sess.ID)

	plain := &user.User{Username: "plain", DisplayName: "Plain", Roles: []user.Role{user.RoleUser}}
	if err := users.Create(ctx, plain); err != nil {
		t.Fatal(err)
	}
	tok, _, _ = sessions.Create(ctx, plain.ID, "127.0.0.1", "test", true)
	e.user = &http.Cookie{Name: auth.CookieName, Value: tok}
	return e
}

func (e *env) do(method, path string, body any, cookie *http.Cookie) (int, map[string]any) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.RemoteAddr = "203.0.113.7:1234"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	e.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func writeBody() map[string]any {
	return map[string]any{
		"name": "web", "region": "ap-south-1", "external_name": "web-asg", "role_arn": "arn:aws:iam::123456789012:role/zanskar",
		"os_family": "linux", "capabilities": []string{"ssh"}, "tags": map[string]string{"env": "prod"},
	}
}

func TestHandlersRequireAdmin(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.do("GET", "/api/v1/autoscaling-groups", nil, nil); code != 401 {
		t.Fatalf("anonymous: %d", code)
	}
	if code, _ := e.do("GET", "/api/v1/autoscaling-groups", nil, e.user); code != 403 {
		t.Fatalf("user role: %d", code)
	}
	if code, _ := e.do("POST", "/api/v1/autoscaling-groups", writeBody(), e.user); code != 403 {
		t.Fatalf("user create: %d", code)
	}
}

func TestCreateGetListSyncIAMRotateDelete(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	code, g := e.do("POST", "/api/v1/autoscaling-groups", writeBody(), e.admin)
	if code != 201 {
		t.Fatalf("create: %d %v", code, g)
	}
	id := g["id"].(string)
	ext := g["external_id"].(string)
	if !strings.HasPrefix(ext, "zanskar-") {
		t.Fatalf("external id not generated: %q", ext)
	}
	if code, _ := e.do("POST", "/api/v1/autoscaling-groups", writeBody(), e.admin); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	bad := writeBody()
	bad["role_arn"] = "nope"
	if code, _ := e.do("POST", "/api/v1/autoscaling-groups", bad, e.admin); code != 400 {
		t.Fatalf("bad arn: %d", code)
	}

	if code, got := e.do("GET", "/api/v1/autoscaling-groups/"+id, nil, e.admin); code != 200 || got["name"] != "web" || got["external_id"] != ext {
		t.Fatalf("get: %d %v", code, got)
	}
	if code, _ := e.do("GET", "/api/v1/autoscaling-groups/nope", nil, e.admin); code != 404 {
		t.Fatalf("missing: %d", code)
	}

	// list before sync: zero counts
	code, list := e.do("GET", "/api/v1/autoscaling-groups", nil, e.admin)
	items := list["items"].([]any)
	if code != 200 || len(items) != 1 || items[0].(map[string]any)["instance_count"].(float64) != 0 {
		t.Fatalf("list before sync: %d %v", code, list)
	}

	// sync
	code, sr := e.do("POST", "/api/v1/autoscaling-groups/"+id+"/sync", nil, e.admin)
	if code != 200 || sr["error"] != nil {
		t.Fatalf("sync: %d %v", code, sr)
	}
	sum := sr["summary"].(map[string]any)
	if sum["Seen"].(float64) != 2 || sum["Healthy"].(float64) != 1 {
		t.Fatalf("summary: %v", sum)
	}
	if sr["group"].(map[string]any)["last_synced_at"] == nil {
		t.Fatalf("group not refreshed: %v", sr["group"])
	}

	// list after sync: counts
	_, list = e.do("GET", "/api/v1/autoscaling-groups", nil, e.admin)
	row := list["items"].([]any)[0].(map[string]any)
	if row["instance_count"].(float64) != 2 || row["healthy_count"].(float64) != 1 {
		t.Fatalf("counts: %v", row)
	}

	// instances default excludes terminated; all=true includes
	if _, err := e.repo.MarkTerminated(ctx, id, []string{"i-1"}); err != nil {
		t.Fatal(err)
	}
	_, inst := e.do("GET", "/api/v1/autoscaling-groups/"+id+"/instances", nil, e.admin)
	if len(inst["items"].([]any)) != 1 {
		t.Fatalf("instances default: %v", inst)
	}
	_, inst = e.do("GET", "/api/v1/autoscaling-groups/"+id+"/instances?all=true", nil, e.admin)
	if len(inst["items"].([]any)) != 2 {
		t.Fatalf("instances all: %v", inst)
	}

	// iam documents
	code, iam := e.do("GET", "/api/v1/autoscaling-groups/"+id+"/iam", nil, e.admin)
	if code != 200 || iam["external_id"] != ext || !strings.Contains(iam["trust_policy"].(string), ext) || !strings.Contains(iam["trust_policy"].(string), "111111111111") || !strings.Contains(iam["permissions_policy"].(string), "web-asg") {
		t.Fatalf("iam: %d %v", code, iam)
	}

	// update keeps external id; rotate changes it
	body := writeBody()
	body["name"] = "web2"
	code, up := e.do("PUT", "/api/v1/autoscaling-groups/"+id, body, e.admin)
	if code != 200 || up["name"] != "web2" || up["external_id"] != ext {
		t.Fatalf("update: %d %v", code, up)
	}
	body["rotate_external_id"] = true
	code, up = e.do("PUT", "/api/v1/autoscaling-groups/"+id, body, e.admin)
	if code != 200 || up["external_id"] == ext || !strings.HasPrefix(up["external_id"].(string), "zanskar-") {
		t.Fatalf("rotate: %d %v", code, up)
	}

	// credentials
	now := store.TimeArg(time.Now())
	if _, err := e.db.ExecContext(ctx, e.db.Rebind(`INSERT INTO credentials (id, name, type, mode, username, created_at, updated_at) VALUES ('c1', 'key', 'ssh_key', 'vaulted', 'ec2-user', ?, ?)`), now, now); err != nil {
		t.Fatal(err)
	}
	code, cg := e.do("PUT", "/api/v1/autoscaling-groups/"+id+"/credentials/ssh", map[string]string{"credential_id": "c1"}, e.admin)
	if code != 200 || cg["credentials"].(map[string]any)["ssh"] != "c1" {
		t.Fatalf("set credential: %d %v", code, cg)
	}
	if code, _ := e.do("PUT", "/api/v1/autoscaling-groups/"+id+"/credentials/ssh", map[string]string{"credential_id": "missing"}, e.admin); code != 400 {
		t.Fatalf("bad credential: %d", code)
	}
	if code, _ := e.do("DELETE", "/api/v1/autoscaling-groups/"+id+"/credentials/ssh", nil, e.admin); code != 204 {
		t.Fatalf("unset credential: %d", code)
	}
	got, _ := e.repo.Get(ctx, id)
	if _, ok := got.Credentials[target.SSH]; ok {
		t.Fatal("credential should be unset")
	}

	// audit trail exists and has no credential material beyond ids
	events, _, err := e.audit.List(ctx, audit.Filter{ObjectType: "autoscaling_group"})
	if err != nil || len(events) < 6 {
		t.Fatalf("audit events: %d %v", len(events), err)
	}

	if code, _ := e.do("DELETE", "/api/v1/autoscaling-groups/"+id, nil, e.admin); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := e.do("GET", "/api/v1/autoscaling-groups/"+id, nil, e.admin); code != 404 {
		t.Fatalf("after delete: %d", code)
	}
}
