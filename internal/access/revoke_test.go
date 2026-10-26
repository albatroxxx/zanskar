// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/gateway"
)

// fakeRevoker stands in for the gateway: it records the grants it was asked
// to end and reports ended sessions for each; anything else is unexpected.
type fakeRevoker struct {
	ended      int
	grants     []string // "user target asg proto", revoked
	expired    []string // the same, expired
	unexpected []string
}

var _ gateway.Revoker = (*fakeRevoker)(nil)

func (f *fakeRevoker) GrantRevoked(_ context.Context, userID, targetID, asgID, proto string) int {
	f.grants = append(f.grants, fmt.Sprintf("%s %s %s %s", userID, targetID, asgID, proto))
	return f.ended
}
func (f *fakeRevoker) GrantExpired(_ context.Context, userID, targetID, asgID, proto string) int {
	f.expired = append(f.expired, fmt.Sprintf("%s %s %s %s", userID, targetID, asgID, proto))
	return f.ended
}
func (f *fakeRevoker) UserRevoked(string) int                    { return f.other("UserRevoked") }
func (f *fakeRevoker) PolicyDeleted(string) int                  { return f.other("PolicyDeleted") }
func (f *fakeRevoker) PolicyChanged(context.Context, string) int { return f.other("PolicyChanged") }
func (f *fakeRevoker) GroupMembersRemoved(context.Context, string, []string) int {
	return f.other("GroupMembersRemoved")
}
func (f *fakeRevoker) GroupDeleted(context.Context, string) int { return f.other("GroupDeleted") }
func (f *fakeRevoker) TargetDisabled(string) int                { return f.other("TargetDisabled") }
func (f *fakeRevoker) TargetTrustLost(string) int               { return f.other("TargetTrustLost") }
func (f *fakeRevoker) other(name string) int {
	f.unexpected = append(f.unexpected, name)
	return 0
}

// TestRevokeEndsTheSessionsTheGrantAdmitted: revoking a grant asks the
// gateway to end the sessions it admitted, scoped to the grant's user,
// target and protocol, and the audit event records how many ended.
func TestRevokeEndsTheSessionsTheGrantAdmitted(t *testing.T) {
	e := newEnv(t)
	e.revoker.ended = 2
	id := e.request(t)
	if code, out := e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, e.admin, e.adminCSR); code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, out)
	}
	if code, out := e.do("POST", "/api/v1/access-requests/"+id+"/revoke", map[string]string{"note": "done"}, e.admin, e.adminCSR); code != http.StatusOK {
		t.Fatalf("revoke: %d %v", code, out)
	}
	want := e.ids["alice"] + " " + e.target + "  ssh"
	if len(e.revoker.grants) != 1 || e.revoker.grants[0] != want || len(e.revoker.unexpected) != 0 {
		t.Fatalf("revoker asked %v (unexpected %v), want [%q]", e.revoker.grants, e.revoker.unexpected, want)
	}
	if _, d := e.lastEvent(t, "access.request.revoke"); d["live_sessions_ended"] != float64(2) {
		t.Fatalf("revoke audit should count the ended sessions: %v", d)
	}
}

// TestApproveUsesThePolicyAsItStandsNow: the cap and the eligibility are
// decided at approve from the current policies, not from the request. A
// maximum lowered since the request bounds the grant, with or without an
// override; a policy that no longer makes the requester eligible refuses it.
func TestApproveUsesThePolicyAsItStandsNow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	id := e.request(t) // 30 minutes under a 120 minute maximum
	pols, err := e.policies.ForUser(ctx, e.ids["alice"])
	if err != nil || len(pols) != 1 {
		t.Fatalf("alice's policies: %v %v", pols, err)
	}
	pol := pols[0]
	most := 20
	pol.MaxSessionMinutes = &most
	if err := e.policies.Update(ctx, pol); err != nil {
		t.Fatal(err)
	}
	code, out := e.do("POST", "/api/v1/access-requests/"+id+"/approve", nil, e.admin, e.adminCSR)
	if code != http.StatusBadRequest || out["code"] != "duration_too_long" || !strings.Contains(out["message"].(string), "20 minutes") {
		t.Fatalf("approve of 30 under a maximum lowered to 20: %d %v, want 400 duration_too_long naming 20", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/approve", map[string]int{"minutes": 25}, e.admin, e.adminCSR); code != http.StatusBadRequest {
		t.Fatalf("override of 25 under a maximum of 20: %d %v, want 400", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/approve", map[string]int{"minutes": 20}, e.admin, e.adminCSR); code != http.StatusOK || out["approved_minutes"] != float64(20) {
		t.Fatalf("approve inside the lowered maximum: %d %v", code, out)
	}
	if code, out = e.do("POST", "/api/v1/access-requests/"+id+"/revoke", nil, e.admin, e.adminCSR); code != http.StatusOK {
		t.Fatalf("revoke: %d %v", code, out)
	}

	// The policy goes away: the pending request cannot be approved at all,
	// and the refusal says why.
	most = 120
	if err := e.policies.Update(ctx, pol); err != nil {
		t.Fatal(err)
	}
	second := e.request(t)
	if err := e.policies.Delete(ctx, pol.ID); err != nil {
		t.Fatal(err)
	}
	code, out = e.do("POST", "/api/v1/access-requests/"+second+"/approve", map[string]int{"minutes": 5}, e.admin, e.adminCSR)
	if code != http.StatusConflict || out["code"] != "not_eligible" {
		t.Fatalf("approve after the policy was deleted: %d %v, want 409 not_eligible", code, out)
	}
	if got, _ := e.requests.Get(ctx, second); got.Status != StatusPending {
		t.Fatalf("a refused approval must leave the request pending, got %s", got.Status)
	}
}

// TestSweeperEndsExpiredGrantSessions: a grant that expires takes its
// sessions with it, as an expiry rather than a revoke so they end as
// max_duration, and the expiry event records how many ended (ADR 0018,
// amended 2026-10-26).
func TestSweeperEndsExpiredGrantSessions(t *testing.T) {
	ctx, r := setup(t)
	lapsed := &Request{UserID: "u1", TargetID: "t1", Protocol: "ssh", Reason: "x", RequestedMinutes: 1}
	if err := r.Create(ctx, lapsed); err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-time.Minute)
	if _, err := r.Decide(ctx, lapsed.ID, "u2", StatusApproved, "", &past, 0); err != nil {
		t.Fatal(err)
	}
	rv := &fakeRevoker{ended: 1}
	sw := &Sweeper{Repo: r, Revoker: rv, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if n, err := sw.Sweep(ctx); err != nil || n != 1 {
		t.Fatalf("sweep: n=%d err=%v", n, err)
	}
	if len(rv.expired) != 1 || rv.expired[0] != "u1 t1  ssh" || len(rv.grants) != 0 || len(rv.unexpected) != 0 {
		t.Fatalf("revoker asked expired %v revoked %v (unexpected %v), want one expiry", rv.expired, rv.grants, rv.unexpected)
	}
}
