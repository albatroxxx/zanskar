// SPDX-License-Identifier: Apache-2.0

package asg

import (
	"context"
	"encoding/json"
	"sort"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/gateway"
)

// fakeRevoker stands in for the gateway: it records the instances it was
// asked to end sessions on and reports ended sessions for each call.
type fakeRevoker struct {
	ended      int
	disabled   []string
	unexpected []string
}

var _ gateway.Revoker = (*fakeRevoker)(nil)

func (f *fakeRevoker) TargetDisabled(id string) int {
	f.disabled = append(f.disabled, id)
	return f.ended
}
func (f *fakeRevoker) UserRevoked(string) int                    { return f.other("UserRevoked") }
func (f *fakeRevoker) PolicyDeleted(string) int                  { return f.other("PolicyDeleted") }
func (f *fakeRevoker) PolicyChanged(context.Context, string) int { return f.other("PolicyChanged") }
func (f *fakeRevoker) GroupMembersRemoved(context.Context, string, []string) int {
	return f.other("GroupMembersRemoved")
}
func (f *fakeRevoker) GroupDeleted(context.Context, string) int { return f.other("GroupDeleted") }
func (f *fakeRevoker) TargetTrustLost(string) int               { return f.other("TargetTrustLost") }
func (f *fakeRevoker) GrantRevoked(context.Context, string, string, string, string) int {
	return f.other("GrantRevoked")
}
func (f *fakeRevoker) GrantExpired(context.Context, string, string, string, string) int {
	return f.other("GrantExpired")
}
func (f *fakeRevoker) other(name string) int {
	f.unexpected = append(f.unexpected, name)
	return 0
}

// TestDisableGroupEndsSessionsOnItsInstances: disabling a group asks the
// gateway to end the sessions on each of its instances (the registry keys
// them by instance row id), once, and the audit event counts them in total.
// A save that keeps the group active, or of a group already disabled, asks
// nothing.
func TestDisableGroupEndsSessionsOnItsInstances(t *testing.T) {
	e := newEnv(t)
	e.revoker.ended = 1
	code, g := e.do("POST", "/api/v1/autoscaling-groups", writeBody(), e.admin)
	if code != 201 {
		t.Fatalf("create: %d %v", code, g)
	}
	id := g["id"].(string)
	if code, out := e.do("POST", "/api/v1/autoscaling-groups/"+id+"/sync", nil, e.admin); code != 200 {
		t.Fatalf("sync: %d %v", code, out)
	}
	instances, err := e.repo.Instances(context.Background(), id, false)
	if err != nil || len(instances) != 2 {
		t.Fatalf("instances after sync: %v %v", instances, err)
	}
	body := func(status string) map[string]any {
		b := writeBody()
		b["status"] = status
		return b
	}
	if code, out := e.do("PUT", "/api/v1/autoscaling-groups/"+id, body("active"), e.admin); code != 200 {
		t.Fatalf("save active: %d %v", code, out)
	}
	if len(e.revoker.disabled) != 0 {
		t.Fatalf("a save that keeps the group active asked the gateway to end sessions: %v", e.revoker.disabled)
	}
	if code, out := e.do("PUT", "/api/v1/autoscaling-groups/"+id, body("disabled"), e.admin); code != 200 || out["status"] != "disabled" {
		t.Fatalf("disable: %d %v", code, out)
	}
	want := []string{instances[0].ID, instances[1].ID}
	got := append([]string(nil), e.revoker.disabled...)
	sort.Strings(want)
	sort.Strings(got)
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("disable asked %v, want the two instances %v", got, want)
	}
	evs, _, err := e.audit.List(context.Background(), audit.Filter{Action: "asg.update", Limit: 1})
	if err != nil || len(evs) == 0 {
		t.Fatalf("asg.update event: %v %v", evs, err)
	}
	var d map[string]any
	_ = json.Unmarshal(evs[0].Details, &d)
	if d["live_sessions_ended"] != float64(2) {
		t.Fatalf("disable audit should count the ended sessions: %v", d)
	}
	if code, out := e.do("PUT", "/api/v1/autoscaling-groups/"+id, body("disabled"), e.admin); code != 200 {
		t.Fatalf("save while disabled: %d %v", code, out)
	}
	if len(e.revoker.disabled) != 2 || len(e.revoker.unexpected) != 0 {
		t.Fatalf("a save of an already disabled group asked again: %v (unexpected %v)", e.revoker.disabled, e.revoker.unexpected)
	}
}
