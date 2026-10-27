// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/albatroxxx/zanskar/internal/gateway"
)

// fakeRevoker stands in for the gateway: it records the targets it was asked
// to end sessions on and reports ended sessions for each call.
type fakeRevoker struct {
	ended      int
	disabled   []string
	trustLost  []string
	unexpected []string
}

var _ gateway.Revoker = (*fakeRevoker)(nil)

func (f *fakeRevoker) TargetDisabled(id string) int {
	f.disabled = append(f.disabled, id)
	return f.ended
}

func (f *fakeRevoker) TargetTrustLost(id string) int {
	f.trustLost = append(f.trustLost, id)
	return f.ended
}
func (f *fakeRevoker) UserRevoked(string) int                    { return f.other("UserRevoked") }
func (f *fakeRevoker) PolicyDeleted(string) int                  { return f.other("PolicyDeleted") }
func (f *fakeRevoker) PolicyChanged(context.Context, string) int { return f.other("PolicyChanged") }
func (f *fakeRevoker) GroupMembersRemoved(context.Context, string, []string) int {
	return f.other("GroupMembersRemoved")
}
func (f *fakeRevoker) GroupDeleted(context.Context, string) int { return f.other("GroupDeleted") }
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

func details(t *testing.T, e *env, action string) map[string]any {
	t.Helper()
	evs := auditActions(t, e, action)
	if len(evs) == 0 {
		t.Fatalf("no %s event", action)
	}
	var d map[string]any
	_ = json.Unmarshal(evs[0].Details, &d)
	return d
}

// TestDisableEndsOpenSessions: disabling a target, or moving its address,
// asks the gateway to end the sessions open on it, once, and the audit event
// counts them. Other edits, and a disable of an already disabled target, ask
// nothing.
func TestDisableEndsOpenSessions(t *testing.T) {
	e := newEnv(t)
	e.revoker.ended = 3
	body := func(address, status string) map[string]any {
		return map[string]any{"name": "web-1", "address": address, "os_family": "linux", "status": status}
	}
	id := e.mkTarget(t, body("10.0.0.5", "active"))
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body("10.0.0.5", "active"), e.admin); code != 200 {
		t.Fatalf("rename: %d %v", code, out)
	}
	if len(e.revoker.disabled) != 0 {
		t.Fatalf("an edit that keeps the target in service asked the gateway to end sessions: %v", e.revoker.disabled)
	}
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body("10.0.0.5", "disabled"), e.admin); code != 200 {
		t.Fatalf("disable: %d %v", code, out)
	}
	if got := e.revoker.disabled; len(got) != 1 || got[0] != id {
		t.Fatalf("disable asked %v, want [%s]", got, id)
	}
	if d := details(t, e, "target.update"); d["live_sessions_ended"] != float64(3) {
		t.Fatalf("disable audit should count the ended sessions: %v", d)
	}
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body("10.0.0.5", "disabled"), e.admin); code != 200 {
		t.Fatalf("save while disabled: %d %v", code, out)
	}
	if len(e.revoker.disabled) != 1 {
		t.Fatalf("a save of an already disabled target asked again: %v", e.revoker.disabled)
	}
	// Back in service at a new address: nothing has trusted the host there,
	// so what was connected to the old address ends.
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body("10.0.0.6", "active"), e.admin); code != 200 {
		t.Fatalf("move: %d %v", code, out)
	}
	if got := e.revoker.disabled; len(got) != 2 || got[1] != id {
		t.Fatalf("address change asked %v, want a second call for %s", got, id)
	}
	if d := details(t, e, "target.update"); d["trust_reset"] != true || d["live_sessions_ended"] != float64(3) {
		t.Fatalf("move audit: %v", d)
	}
	if len(e.revoker.unexpected) != 0 {
		t.Fatalf("unexpected revoker calls: %v", e.revoker.unexpected)
	}
}

// TestChangedHostKeyEndsOpenSessions: a probe that finds the trusted host
// key replaced asks the gateway to end the sessions open on the target,
// and the alarm event counts them. A probe that finds the same key asks
// nothing.
func TestChangedHostKeyEndsOpenSessions(t *testing.T) {
	e := newEnv(t)
	e.revoker.ended = 1
	portA, fpA := startSSHServer(t)
	portB, _ := startSSHServer(t)
	body := func(port int) map[string]any {
		return map[string]any{"name": "rekeyed", "address": "127.0.0.1", "os_family": "linux", "ports": map[string]int{"ssh": port, "rdp": 1, "vnc": 1, "winrm": 1}}
	}
	id := e.mkTarget(t, body(portA))
	for _, step := range []string{"probe", "trust", "probe again"} {
		var code int
		var out map[string]any
		switch step {
		case "trust":
			code, out = e.do("POST", "/api/v1/targets/"+id+"/host-key/trust", map[string]string{"host_key_fingerprint": fpA}, e.admin)
		default:
			code, out = e.do("POST", "/api/v1/targets/"+id+"/probe", nil, e.admin)
		}
		if code != 200 {
			t.Fatalf("%s: %d %v", step, code, out)
		}
	}
	if len(e.revoker.trustLost) != 0 {
		t.Fatalf("a probe that found the trusted key asked the gateway to end sessions: %v", e.revoker.trustLost)
	}
	if code, out := e.do("PUT", "/api/v1/targets/"+id, body(portB), e.admin); code != 200 {
		t.Fatalf("port change: %d %v", code, out)
	}
	if code, out := e.do("POST", "/api/v1/targets/"+id+"/probe", nil, e.admin); code != 200 || out["host_key_status"] != "changed" {
		t.Fatalf("changed key: %d %v", code, out)
	}
	if got := e.revoker.trustLost; len(got) != 1 || got[0] != id {
		t.Fatalf("changed key asked %v, want [%s]", got, id)
	}
	if d := details(t, e, "target.hostkey.changed"); d["live_sessions_ended"] != float64(1) {
		t.Fatalf("changed-key audit should count the ended sessions: %v", d)
	}
	if len(e.revoker.unexpected) != 0 {
		t.Fatalf("unexpected revoker calls: %v", e.revoker.unexpected)
	}
}
