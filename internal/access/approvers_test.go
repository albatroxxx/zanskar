// SPDX-License-Identifier: Apache-2.0

package access

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/notify"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/policy/policytest"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/user"
)

// named is the second approval policy the approver tests add (ADR 0049):
// alice is eligible for the prod hosts over ssh under it too, and it names
// the group "approvers" (carol in it) and dan as the approvers. erin holds
// the approver role and is named nowhere.
type named struct {
	group                string
	carol, dan, erin     *http.Cookie
	carolSR, danSR, erSR string
	policy               *policy.Policy
}

func (e *env) nameApprovers(t *testing.T) *named {
	t.Helper()
	ctx := context.Background()
	n := &named{}
	// carol and erin hold the role alone, which decides and connects to
	// nothing; dan also holds user, so he may request access himself.
	n.carol, n.carolSR = e.login("carol", user.RoleApprover)
	n.dan, n.danSR = e.login("dan", user.RoleApprover, user.RoleUser)
	n.erin, n.erSR = e.login("erin", user.RoleApprover)
	g := &group.Group{Name: "approvers"}
	if err := e.groups.CreateWithMembers(ctx, g, []string{e.ids["carol"]}); err != nil {
		t.Fatal(err)
	}
	n.group = g.ID
	grant := policytest.Approval(policytest.Tagged(protocol.KindHost, map[string]string{"env": "prod"}, "ssh"), 120)
	grant.Approvers = []policy.Subject{policytest.Group(g.ID), policytest.User(e.ids["dan"])}
	n.policy = policytest.Policy("prod-named", []policy.Subject{policytest.User(e.ids["alice"])}, grant)
	if err := e.policies.Create(ctx, n.policy); err != nil {
		t.Fatal(err)
	}
	return n
}

func approverNamesOf(out map[string]any) []string {
	list, _ := out["approvers"].([]any)
	var got []string
	for _, a := range list {
		got = append(got, a.(map[string]any)["name"].(string))
	}
	return got
}

// TestNamedApproversDecide: where a grant names approvers, they alone
// approve and deny, an administrator is refused by name and may still
// revoke, an approver named nowhere is refused, and the queue shows the
// names and scopes itself to the approver (ADR 0049, 4 and 5).
func TestNamedApproversDecide(t *testing.T) {
	e := newEnv(t)
	n := e.nameApprovers(t)
	ctx := context.Background()
	code, out := e.do("POST", "/api/v1/me/access-requests", map[string]any{"target_id": e.target, "protocol": "ssh", "reason": "deploy", "minutes": 30}, e.alice, e.aliceCSR)
	if code != http.StatusCreated || out["named"] != true || strings.Join(approverNamesOf(out), ",") != "approvers,dan" {
		t.Fatalf("request: %d %v", code, out)
	}
	id := out["id"].(string)
	if _, d := e.lastEvent(t, "access.request.create"); d["named_approvers"] != true {
		t.Fatalf("the create event should say approvers are named: %v", d)
	}

	// The administrator sees it with its approvers and cannot decide it.
	code, out = e.do("GET", "/api/v1/access-requests?status=pending", nil, e.admin, e.adminCSR)
	items := out["items"].([]any)
	if code != 200 || len(items) != 1 || strings.Join(approverNamesOf(items[0].(map[string]any)), ",") != "approvers,dan" {
		t.Fatalf("admin queue: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, e.admin, e.adminCSR); code != http.StatusForbidden || out["code"] != "approvers_named" {
		t.Fatalf("admin approve on a named request: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/deny", nil, e.admin, e.adminCSR); code != http.StatusForbidden || out["code"] != "approvers_named" {
		t.Fatalf("admin deny on a named request: %d %v", code, out)
	}

	// An approver named nowhere sees nothing and decides nothing.
	code, out = e.do("GET", "/api/v1/access-requests", nil, n.erin, n.erSR)
	if code != 200 || len(out["items"].([]any)) != 0 {
		t.Fatalf("erin's queue should be empty: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, n.erin, n.erSR); code != http.StatusForbidden || out["code"] != "forbidden" {
		t.Fatalf("erin approve: %d %v", code, out)
	}
	// Outside her scope the request is not found, as another person's is
	// for its requester: the id alone tells her nothing.
	if code, out = e.do("GET", "/api/v1/access-requests/"+id, nil, n.erin, n.erSR); code != http.StatusNotFound || out["code"] != "not_found" {
		t.Fatalf("erin reads a request she is not named for: %d %v", code, out)
	}
	// A user without the role never reaches the queue.
	if code, _ := e.do("GET", "/api/v1/access-requests", nil, e.alice, e.aliceCSR); code != http.StatusForbidden {
		t.Fatalf("a user listed the queue: %d", code)
	}

	// carol, through the group: the queue is hers without asking for scope,
	// the request opens, and she approves it.
	code, out = e.do("GET", "/api/v1/access-requests", nil, n.carol, n.carolSR)
	if code != 200 || len(out["items"].([]any)) != 1 {
		t.Fatalf("carol's queue: %d %v", code, out)
	}
	if code, out = e.do("GET", "/api/v1/access-requests/"+id, nil, n.carol, n.carolSR); code != 200 || out["named"] != true {
		t.Fatalf("carol reads the request: %d %v", code, out)
	}
	code, out = e.do("POST", "/api/v1/access-requests/"+id+"/approve", map[string]any{"minutes": 45, "note": "ok"}, n.carol, n.carolSR)
	if code != 200 || out["status"] != "approved" || out["approver_username"] != "carol" || out["approved_minutes"] != float64(45) {
		t.Fatalf("carol approve: %d %v", code, out)
	}
	// The active grant is in the view of everyone who may revoke it (ADR
	// 0049, 5): carol, who approved it, and dan, named on the same grant.
	for who, c := range map[string]struct {
		cookie *http.Cookie
		csrf   string
	}{"carol": {n.carol, n.carolSR}, "dan": {n.dan, n.danSR}} {
		for _, q := range []string{"?scope=mine", "?scope=mine&status=approved"} {
			code, out = e.do("GET", "/api/v1/access-requests"+q, nil, c.cookie, c.csrf)
			if code != 200 || len(out["items"].([]any)) != 1 || out["items"].([]any)[0].(map[string]any)["status"] != "approved" {
				t.Fatalf("%s's active grants %s: %d %v", who, q, code, out)
			}
		}
	}
	// carol un-named by a policy edit: the grant she approved leaves her
	// view while it runs (she may not revoke it), and is her history once it
	// no longer does.
	n.policy.Grants[0].Approvers = []policy.Subject{policytest.User(e.ids["dan"])}
	if err := e.policies.Update(ctx, n.policy); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"?scope=mine", "?scope=mine&status=approved"} {
		if code, out = e.do("GET", "/api/v1/access-requests"+q, nil, n.carol, n.carolSR); code != 200 || len(out["items"].([]any)) != 0 {
			t.Fatalf("carol's view once un-named %s: %d %v", q, code, out)
		}
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/revoke", nil, n.carol, n.carolSR); code != http.StatusForbidden {
		t.Fatalf("carol revokes once un-named: %d %v", code, out)
	}
	// dan, named directly, may revoke what carol granted; erin may not; the
	// administrator always may.
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/revoke", nil, n.erin, n.erSR); code != http.StatusForbidden {
		t.Fatalf("erin revoke: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/revoke", nil, n.dan, n.danSR); code != 200 || out["status"] != "revoked" {
		t.Fatalf("dan revoke: %d %v", code, out)
	}
	code, out = e.do("GET", "/api/v1/access-requests?scope=mine", nil, n.carol, n.carolSR)
	if code != 200 || len(out["items"].([]any)) != 1 || out["items"].([]any)[0].(map[string]any)["status"] != "revoked" {
		t.Fatalf("carol's history: %d %v", code, out)
	}
	// Second round: the administrator revokes a named grant.
	id = e.request(t)
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, n.dan, n.danSR); code != 200 {
		t.Fatalf("dan approve: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/revoke", nil, e.admin, e.adminCSR); code != 200 || out["status"] != "revoked" {
		t.Fatalf("admin revoke on a named grant: %d %v", code, out)
	}
	// scope=mine with a status the approver never set is empty, and an
	// unknown scope is refused.
	if code, out = e.do("GET", "/api/v1/access-requests?scope=mine&status=denied", nil, n.dan, n.danSR); code != 200 || len(out["items"].([]any)) != 0 {
		t.Fatalf("dan's denied: %d %v", code, out)
	}
	if code, _ = e.do("GET", "/api/v1/access-requests?scope=theirs", nil, e.admin, e.adminCSR); code != http.StatusBadRequest {
		t.Fatalf("unknown scope: %d", code)
	}
}

// TestUnnamedStaysWithAdmins: a request no grant names approvers for is
// the administrator's, as before; an approver, however the role, is
// refused on it.
func TestUnnamedStaysWithAdmins(t *testing.T) {
	e := newEnv(t)
	erin, erinCSR := e.login("erin", user.RoleApprover)
	id := e.request(t)
	code, out := e.do("GET", "/api/v1/access-requests/"+id, nil, e.admin, e.adminCSR)
	if code != 200 || out["named"] != false || len(out["approvers"].([]any)) != 0 {
		t.Fatalf("unnamed request: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, erin, erinCSR); code != http.StatusForbidden || out["code"] != "forbidden" {
		t.Fatalf("an approver on an unnamed request: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, e.admin, e.adminCSR); code != 200 {
		t.Fatalf("admin approve: %d %v", code, out)
	}
}

// TestNobodyDecidesTheirOwn: a named approver never decides their own
// request, and a request nobody but its author could decide is refused
// when made (ADR 0049, 4; TEAM blocks the same case).
func TestNobodyDecidesTheirOwn(t *testing.T) {
	e := newEnv(t)
	n := e.nameApprovers(t)
	ctx := context.Background()
	// dan alone is named to approve what dan may request.
	self := policytest.Approval(policytest.Tagged(protocol.KindHost, map[string]string{"env": "prod"}, "rdp"), 60)
	self.Approvers = []policy.Subject{policytest.User(e.ids["dan"])}
	pol := policytest.Policy("dan-alone", []policy.Subject{policytest.User(e.ids["dan"])}, self)
	if err := e.policies.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}
	ask := func() (int, map[string]any) {
		return e.do("POST", "/api/v1/me/access-requests", map[string]any{"target_id": e.target, "protocol": "rdp", "reason": "patch", "minutes": 30}, n.dan, n.danSR)
	}
	// The refusal names the policy and nothing else: not the approvers (a
	// user is told no other person's name) and no next step.
	code, out := ask()
	if code != http.StatusUnprocessableEntity || out["code"] != "no_approver" || out["message"] != "nobody else is named to approve this request (policy dan-alone)" {
		t.Fatalf("a request only its author could approve: %d %v", code, out)
	}
	// With carol's group named too, the request waits for her; dan is
	// refused on his own.
	pol.Grants[0].Approvers = append(pol.Grants[0].Approvers, policytest.Group(n.group))
	if err := e.policies.Update(ctx, pol); err != nil {
		t.Fatal(err)
	}
	code, out = ask()
	if code != http.StatusCreated {
		t.Fatalf("request: %d %v", code, out)
	}
	id := out["id"].(string)
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, n.dan, n.danSR); code != http.StatusForbidden || out["code"] != "own_request" {
		t.Fatalf("dan approves his own: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/deny", nil, n.dan, n.danSR); code != http.StatusForbidden || out["code"] != "own_request" {
		t.Fatalf("dan denies his own: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, n.carol, n.carolSR); code != 200 {
		t.Fatalf("carol approves dan's: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/revoke", nil, n.dan, n.danSR); code != http.StatusForbidden || out["code"] != "own_request" {
		t.Fatalf("dan revokes his own: %d %v", code, out)
	}
}

// TestNamedWithoutTheRoleDecidesNothing: a user named on a grant who does
// not hold the approver role is not a decider (the route refuses them and
// they count for nobody), so a request they alone are named for is refused.
func TestNamedWithoutTheRoleDecidesNothing(t *testing.T) {
	e := newEnv(t)
	e.login("bob", user.RoleUser)
	ctx := context.Background()
	grant := policytest.Approval(policytest.Tagged(protocol.KindHost, map[string]string{"env": "prod"}, "rdp"), 60)
	grant.Approvers = []policy.Subject{policytest.User(e.ids["bob"])}
	if err := e.policies.Create(ctx, policytest.Policy("bob-named", []policy.Subject{policytest.User(e.ids["alice"])}, grant)); err != nil {
		t.Fatal(err)
	}
	code, out := e.do("POST", "/api/v1/me/access-requests", map[string]any{"target_id": e.target, "protocol": "rdp", "reason": "patch", "minutes": 30}, e.alice, e.aliceCSR)
	if code != http.StatusUnprocessableEntity || out["code"] != "no_approver" {
		t.Fatalf("named without the role: %d %v", code, out)
	}
}

// TestMayDecide: a request says whether the caller who reads it may decide
// it now (ADR 0049, 1 and 4): an administrator where nobody is named; where
// someone is, the named who are not the requester, an administrator among
// them when a grant names them (the console draws its buttons from this).
func TestMayDecide(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Nobody named: the administrator's.
	id := e.request(t)
	code, out := e.do("GET", "/api/v1/access-requests/"+id, nil, e.admin, e.adminCSR)
	if code != 200 || out["named"] != false || out["may_decide"] != true {
		t.Fatalf("unnamed, admin: %d %v", code, out)
	}
	// Named for carol's group and dan: not the administrator's any more;
	// dan's, in his view.
	n := e.nameApprovers(t)
	if code, out = e.do("GET", "/api/v1/access-requests/"+id, nil, e.admin, e.adminCSR); code != 200 || out["named"] != true || out["may_decide"] != false {
		t.Fatalf("named, admin: %d %v", code, out)
	}
	code, out = e.do("GET", "/api/v1/access-requests?status=pending", nil, e.admin, e.adminCSR)
	if code != 200 || out["items"].([]any)[0].(map[string]any)["may_decide"] != false {
		t.Fatalf("named, admin queue: %d %v", code, out)
	}
	code, out = e.do("GET", "/api/v1/access-requests", nil, n.dan, n.danSR)
	if code != 200 || len(out["items"].([]any)) != 1 || out["items"].([]any)[0].(map[string]any)["may_decide"] != true {
		t.Fatalf("named, dan's queue: %d %v", code, out)
	}
	// The requester never: dan asks under a grant naming him and carol's
	// group; his view says it is not his to decide, carol's says it is hers.
	self := policytest.Approval(policytest.Tagged(protocol.KindHost, map[string]string{"env": "prod"}, "vnc"), 60)
	self.Approvers = []policy.Subject{policytest.User(e.ids["dan"]), policytest.Group(n.group)}
	if err := e.policies.Create(ctx, policytest.Policy("dan-and-carol", []policy.Subject{policytest.User(e.ids["dan"])}, self)); err != nil {
		t.Fatal(err)
	}
	code, out = e.do("POST", "/api/v1/me/access-requests", map[string]any{"target_id": e.target, "protocol": "vnc", "reason": "patch", "minutes": 30}, n.dan, n.danSR)
	if code != http.StatusCreated || out["may_decide"] != false {
		t.Fatalf("dan's own request: %d %v", code, out)
	}
	own := out["id"].(string)
	for who, c := range map[string]struct {
		cookie *http.Cookie
		csrf   string
		want   bool
	}{"dan": {n.dan, n.danSR, false}, "carol": {n.carol, n.carolSR, true}} {
		if code, out = e.do("GET", "/api/v1/access-requests/"+own, nil, c.cookie, c.csrf); code != 200 || out["may_decide"] != c.want {
			t.Fatalf("%s reads dan's own request: %d %v", who, code, out)
		}
	}
	// A grant naming the administrator: they decide it, from either view,
	// as the ADR has an administrator who should decide join the approvers.
	root := policytest.Approval(policytest.Tagged(protocol.KindHost, map[string]string{"env": "prod"}, "rdp"), 60)
	root.Approvers = []policy.Subject{policytest.User(e.ids["root"])}
	if err := e.policies.Create(ctx, policytest.Policy("root-named", []policy.Subject{policytest.User(e.ids["alice"])}, root)); err != nil {
		t.Fatal(err)
	}
	code, out = e.do("POST", "/api/v1/me/access-requests", map[string]any{"target_id": e.target, "protocol": "rdp", "reason": "patch", "minutes": 30}, e.alice, e.aliceCSR)
	if code != http.StatusCreated || out["named"] != true || strings.Join(approverNamesOf(out), ",") != "root" {
		t.Fatalf("request naming the administrator: %d %v", code, out)
	}
	named := out["id"].(string)
	if code, out = e.do("GET", "/api/v1/access-requests/"+named, nil, e.admin, e.adminCSR); code != 200 || out["may_decide"] != true {
		t.Fatalf("named administrator reads it: %d %v", code, out)
	}
	code, out = e.do("GET", "/api/v1/access-requests?scope=mine&status=pending", nil, e.admin, e.adminCSR)
	if code != 200 || len(out["items"].([]any)) != 1 || out["items"].([]any)[0].(map[string]any)["id"] != named || out["items"].([]any)[0].(map[string]any)["may_decide"] != true {
		t.Fatalf("named administrator's own view: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+named+"/approve", nil, e.admin, e.adminCSR); code != 200 || out["status"] != "approved" || out["approver_username"] != "root" {
		t.Fatalf("named administrator approves: %d %v", code, out)
	}
	// Decided: nobody may decide it any more.
	if code, out = e.do("GET", "/api/v1/access-requests/"+named, nil, e.admin, e.adminCSR); code != 200 || out["may_decide"] != false {
		t.Fatalf("a decided request: %d %v", code, out)
	}
}

// TestDisabledApproverDecidesNothing: a disabled account is not among a
// request's deciders, so a request only it could approve is refused when
// made, and it is not written to.
func TestDisabledApproverDecidesNothing(t *testing.T) {
	e := newEnv(t)
	n := e.nameApprovers(t)
	ctx := context.Background()
	for _, who := range []string{"carol", "dan"} {
		if err := e.users.Update(ctx, e.ids[who], who, who+"@example.com", user.StatusActive); err != nil {
			t.Fatal(err)
		}
	}
	// carol's group alone is named for rdp; with carol disabled nobody is.
	alone := policytest.Approval(policytest.Tagged(protocol.KindHost, map[string]string{"env": "prod"}, "rdp"), 60)
	alone.Approvers = []policy.Subject{policytest.Group(n.group)}
	if err := e.policies.Create(ctx, policytest.Policy("carol-alone", []policy.Subject{policytest.User(e.ids["alice"])}, alone)); err != nil {
		t.Fatal(err)
	}
	ask := func() (int, map[string]any) {
		return e.do("POST", "/api/v1/me/access-requests", map[string]any{"target_id": e.target, "protocol": "rdp", "reason": "patch", "minutes": 30}, e.alice, e.aliceCSR)
	}
	if err := e.users.Update(ctx, e.ids["carol"], "carol", "carol@example.com", user.StatusDisabled); err != nil {
		t.Fatal(err)
	}
	if code, out := ask(); code != http.StatusUnprocessableEntity || out["code"] != "no_approver" {
		t.Fatalf("the only approver disabled: %d %v", code, out)
	}
	// Over ssh dan is named too: the request is made, and the mail reaches
	// dan alone.
	port, got := fakeSMTP(t)
	e.h.Mail = &notify.Direct{Sender: &notify.Sender{}, Base: "https://gw.example.com/",
		Server: func(context.Context) (*notify.Server, error) {
			return &notify.Server{Host: "127.0.0.1", Port: port, From: "gw@example.com"}, nil
		}}
	e.request(t)
	deadline := time.Now().Add(5 * time.Second)
	var mail string
	for time.Now().Before(deadline) {
		if mail = got(); strings.Contains(mail, "Zanskar,") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(mail, "To: dan@example.com\r\n") || strings.Contains(mail, "carol@") {
		t.Fatalf("the mail should reach dan alone:\n%s", mail)
	}
	// Enabled again, carol counts: the rdp request is made.
	if err := e.users.Update(ctx, e.ids["carol"], "carol", "carol@example.com", user.StatusActive); err != nil {
		t.Fatal(err)
	}
	if code, out := ask(); code != http.StatusCreated {
		t.Fatalf("the approver enabled again: %d %v", code, out)
	}
}

// TestCancelAndEnd: the requester withdraws a pending request and ends
// their own active grant (ADR 0049, 8); nobody else's, and never twice.
func TestCancelAndEnd(t *testing.T) {
	e := newEnv(t)
	bob, bobCSR := e.login("bob", user.RoleUser)
	id := e.request(t)
	if code, out := e.do("POST", "/api/v1/me/access-requests/"+id+"/cancel", nil, bob, bobCSR); code != http.StatusNotFound {
		t.Fatalf("bob cancels alice's: %d %v", code, out)
	}
	code, out := e.do("POST", "/api/v1/me/access-requests/"+id+"/cancel", nil, e.alice, e.aliceCSR)
	if code != 200 || out["status"] != "cancelled" || out["state"] != "cancelled" {
		t.Fatalf("cancel: %d %v", code, out)
	}
	if ev, _ := e.lastEvent(t, "access.request.cancel"); ev.ActorUserID != e.ids["alice"] {
		t.Fatalf("cancel event actor: %v", ev.ActorUserID)
	}
	if code, out = e.do("POST", "/api/v1/me/access-requests/"+id+"/cancel", nil, e.alice, e.aliceCSR); code != http.StatusConflict || !strings.Contains(out["message"].(string), "cancelled") {
		t.Fatalf("cancel twice: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, e.admin, e.adminCSR); code != http.StatusConflict {
		t.Fatalf("approve a cancelled request: %d %v", code, out)
	}
	// A cancelled request frees the tuple: a new one may be made.
	id = e.request(t)
	if code, out = e.do("POST", "/api/v1/me/access-requests/"+id+"/end", nil, e.alice, e.aliceCSR); code != http.StatusConflict {
		t.Fatalf("end a pending request: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/approve", map[string]any{"note": "fine"}, e.admin, e.adminCSR); code != 200 {
		t.Fatalf("approve: %d %v", code, out)
	}
	e.revoker.ended = 1
	if code, out = e.do("POST", "/api/v1/me/access-requests/"+id+"/end", nil, bob, bobCSR); code != http.StatusNotFound {
		t.Fatalf("bob ends alice's: %d %v", code, out)
	}
	code, out = e.do("POST", "/api/v1/me/access-requests/"+id+"/end", nil, e.alice, e.aliceCSR)
	if code != 200 || out["status"] != "revoked" || out["decision_note"] != "fine" {
		t.Fatalf("end: %d %v", code, out)
	}
	if len(e.revoker.grants) != 1 {
		t.Fatalf("ending a grant should end its sessions: %v", e.revoker.grants)
	}
	if ev, d := e.lastEvent(t, "access.request.revoke"); ev.ActorUserID != e.ids["alice"] || d["by"] != "requester" || d["live_sessions_ended"] != float64(1) {
		t.Fatalf("end event: %v %v", ev.ActorUserID, d)
	}
	if code, out = e.do("POST", "/api/v1/me/access-requests/"+id+"/end", nil, e.alice, e.aliceCSR); code != http.StatusConflict {
		t.Fatalf("end twice: %d %v", code, out)
	}
}

// TestApproversAreMailed: a request with named approvers mails each of them
// who has an address, one message each, through the gateway's mail server,
// with the link to the approvals view; the requester and those without an
// address are left out (ADR 0049, 6).
func TestApproversAreMailed(t *testing.T) {
	e := newEnv(t)
	e.nameApprovers(t)
	ctx := context.Background()
	for _, who := range []string{"carol", "dan"} {
		if err := e.users.Update(ctx, e.ids[who], who, who+"@example.com", user.StatusActive); err != nil {
			t.Fatal(err)
		}
	}
	port, got := fakeSMTP(t)
	e.h.Mail = &notify.Direct{Sender: &notify.Sender{}, Base: "https://gw.example.com/",
		Server: func(context.Context) (*notify.Server, error) {
			return &notify.Server{Host: "127.0.0.1", Port: port, From: "gw@example.com"}, nil
		}}
	id := e.request(t)
	deadline := time.Now().Add(5 * time.Second)
	var mail string
	for time.Now().Before(deadline) {
		if mail = got(); strings.Count(mail, "Zanskar,") == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, want := range []string{"To: carol@example.com\r\n", "To: dan@example.com\r\n", "alice asks for SSH access to web-1", "https://gw.example.com/approvals?request=" + id} {
		if !strings.Contains(mail, want) {
			t.Fatalf("the mail lacks %q:\n%s", want, mail)
		}
	}
	// One message each: carol is not shown dan's address nor dan carol's.
	if strings.Contains(mail, "carol@example.com, dan@example.com") || strings.Count(mail, "Subject:") != 2 {
		t.Fatalf("one message per approver:\n%s", mail)
	}
	if strings.Contains(mail, "erin") || strings.Contains(mail, "event 0") {
		t.Fatalf("the mail names an approver without an address, or an event it has not:\n%s", mail)
	}
}

// fakeSMTP is enough of a mail server for a few messages, one connection at
// a time: no TLS, which the sender allows only for this host's own server.
func fakeSMTP(t *testing.T) (port int, got func() string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var msg strings.Builder
	serve := func(c net.Conn) {
		defer func() { _ = c.Close() }()
		r := bufio.NewReader(c)
		say := func(s string) { _, _ = fmt.Fprintf(c, "%s\r\n", s) }
		say("220 fake ESMTP")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					say("250 queued")
					continue
				}
				mu.Lock()
				msg.WriteString(line)
				mu.Unlock()
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 fake")
			case strings.HasPrefix(cmd, "DATA"):
				inData = true
				say("354 go on")
			case strings.HasPrefix(cmd, "QUIT"):
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}
	// One connection after another: a message per recipient (ADR 0049,
	// review R7) arrives as several, and got returns them end to end.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			serve(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() string {
		mu.Lock()
		defer mu.Unlock()
		return msg.String()
	}
}
