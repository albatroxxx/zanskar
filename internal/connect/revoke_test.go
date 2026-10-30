// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/policy/policytest"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

// liveShell opens an SSH session as alice and returns its id once the bridge
// names it, by which time the session is in the registry. Nothing more is
// typed: the shell sits at its prompt until something ends it.
func (r *terminalRig) liveShell(t *testing.T, ctx context.Context) string {
	t.Helper()
	ws, _, err := r.dial(ctx, r.ticket(t)) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.CloseNow() })
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var c termFrame
		if typ == websocket.MessageText && json.Unmarshal(data, &c) == nil && c.T == "ready" {
			return c.SessionID
		}
	}
}

// endedWith waits for a session's row to close and its session.end event to
// be written, and returns the reason each gives.
func (f *connectFixture) endedWith(t *testing.T, sessionID string) (row, audited string) {
	t.Helper()
	for range 250 {
		s, err := f.h.Sessions.Get(f.ctx, sessionID)
		if err == nil && s.EndedAt != nil {
			evs, _, err := f.auditLog.List(f.ctx, audit.Filter{Action: "session.end", ObjectID: sessionID})
			if err == nil && len(evs) == 1 {
				var d map[string]string
				_ = json.Unmarshal(evs[0].Details, &d)
				return s.EndReason, d["reason"]
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("session %s never ended", sessionID)
	return "", ""
}

// revoked asserts that a session ended because its access was withdrawn.
func (f *connectFixture) revoked(t *testing.T, sessionID string) {
	t.Helper()
	if row, audited := f.endedWith(t, sessionID); row != session.EndPolicyRevoked || audited != session.EndPolicyRevoked {
		t.Fatalf("session %s ended %q (session.end says %q), want %q", sessionID, row, audited, session.EndPolicyRevoked)
	}
}

// stillLive asserts that a session survived: a moment after the change it is
// in the registry, its context is not cancelled and its row is open.
func (f *connectFixture) stillLive(t *testing.T, sessionID string) {
	t.Helper()
	time.Sleep(100 * time.Millisecond)
	if _, ok := f.h.Registry.Get(sessionID); !ok {
		t.Fatalf("session %s left the registry", sessionID)
	}
	if s, err := f.h.Sessions.Get(f.ctx, sessionID); err != nil || s.EndedAt != nil {
		t.Fatalf("session %s row: %+v %v, want open", sessionID, s, err)
	}
}

// bystander registers a live entry for another user under policyID with no
// bridge behind it, and returns the context a revocation would cancel.
func (f *connectFixture) bystander(t *testing.T, policyID string) context.Context {
	t.Helper()
	ctx := f.h.Registry.Add(context.Background(), gateway.Live{SessionID: "bystander", UserID: "someone-else", TargetID: "t", Protocol: "ssh", PolicyID: policyID})
	t.Cleanup(func() { f.h.Registry.Remove("bystander") })
	return ctx
}

func revokeCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestRecheckGroupMemberRemoved (ADR 0036): alice reaches the shell through
// test-all, which names her group. Once she is out of the group nothing
// grants her that session, so the re-check ends it as policy_revoked, on its
// row and in its session.end event. Another user's session is not looked at.
func TestRecheckGroupMemberRemoved(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx := revokeCtx(t)
	id := r.liveShell(t, ctx)
	testAll := r.policyIDs["test-all"]
	if l, _ := r.h.Registry.Get(id); l.PolicyID != testAll {
		t.Fatalf("live session carries policy %q, want test-all (%s)", l.PolicyID, testAll)
	}
	other := r.bystander(t, testAll)

	if err := r.groups.RemoveMember(r.ctx, r.opsID, r.alice.ID); err != nil {
		t.Fatal(err)
	}
	if n := r.h.Recheck(r.ctx, []string{r.alice.ID}); n != 1 {
		t.Fatalf("Recheck ended %d session(s), want 1", n)
	}
	r.revoked(t, id)
	if other.Err() != nil {
		t.Fatal("another user's session was ended")
	}
}

// TestRecheckPolicyDeleted: once the policy that admitted a session is gone
// and nothing else covers it, the re-check ends it as policy_revoked.
func TestRecheckPolicyDeleted(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx := revokeCtx(t)
	id := r.liveShell(t, ctx)
	if err := r.h.Policies.Delete(r.ctx, r.policyIDs["test-all"]); err != nil {
		t.Fatal(err)
	}
	if n := r.h.Recheck(r.ctx, []string{r.alice.ID}); n != 1 {
		t.Fatalf("Recheck ended %d session(s), want 1", n)
	}
	r.revoked(t, id)
}

// TestRecheckGroupDeleted: deleting alice's group takes it out of test-all,
// which stays (ADR 0036); her session, re-checked once the group is gone,
// ends.
func TestRecheckGroupDeleted(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx := revokeCtx(t)
	id := r.liveShell(t, ctx)
	if _, err := r.groups.Delete(r.ctx, r.opsID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.h.Policies.Get(r.ctx, r.policyIDs["test-all"]); err != nil {
		t.Fatalf("test-all went with the group: %v", err)
	}
	if n := r.h.Recheck(r.ctx, []string{r.alice.ID}); n != 1 {
		t.Fatalf("Recheck ended %d session(s), want 1", n)
	}
	r.revoked(t, id)
}

// windowAround is a daily UTC window from half an hour before at to half an
// hour after it.
func windowAround(at time.Time) policy.TimeWindow {
	at = at.UTC()
	return policy.TimeWindow{Days: []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"},
		From: at.Add(-30 * time.Minute).Format("15:04"), To: at.Add(30 * time.Minute).Format("15:04"), TZ: "UTC"}
}

// hostGrant is test-all's host grant, the one alice's shell runs under.
func hostGrant(p *policy.Policy) *policy.Grant {
	for i := range p.Grants {
		if p.Grants[i].Kind == protocol.KindHost {
			return &p.Grants[i]
		}
	}
	return nil
}

// TestRecheckAfterEdit (ADR 0036): an edit to test-all re-checks alice's
// session against all her access as it stands. A refusal a fresh connect
// would meet (protocol dropped, policy disabled, tags moved off the target,
// subject moved off her, approval or an authenticator now required and not
// held) ends it, and so does the clipboard turned off; a shorter idle
// timeout or maximum, a window shut now, or an edit that still grants it
// leaves it running.
func TestRecheckAfterEdit(t *testing.T) {
	cases := []struct {
		name   string
		before func(p *policy.Policy) // applied before the session opens
		edit   func(t *testing.T, r *terminalRig, p *policy.Policy)
		ends   bool
	}{
		{"protocol dropped", nil, func(_ *testing.T, _ *terminalRig, p *policy.Policy) {
			hostGrant(p).Tags.Protocols = []string{"rdp", "winrm"}
		}, true},
		{"policy disabled", nil, func(_ *testing.T, _ *terminalRig, p *policy.Policy) { p.Enabled = false }, true},
		{"tags moved off the target", nil, func(_ *testing.T, _ *terminalRig, p *policy.Policy) {
			hostGrant(p).Tags.Match = map[string][]string{"env": {"prod"}}
		}, true},
		{"subject moved to another user", nil, func(t *testing.T, r *terminalRig, p *policy.Policy) {
			bob := &user.User{Username: "bob", DisplayName: "Bob", Roles: []user.Role{user.RoleUser}}
			if err := r.users.Create(r.ctx, bob); err != nil {
				t.Fatal(err)
			}
			p.Subjects = []policy.Subject{policytest.User(bob.ID)}
		}, true},
		{"approval now required, no grant", nil, func(_ *testing.T, _ *terminalRig, p *policy.Policy) {
			hostGrant(p).Access = policy.AccessApproval
		}, true},
		{"approval now required, grant active", nil, func(t *testing.T, r *terminalRig, p *policy.Policy) {
			hostGrant(p).Access = policy.AccessApproval
			r.grant(t, r.targetID)
		}, false},
		{"authenticator now required, none enrolled", nil, func(_ *testing.T, _ *terminalRig, p *policy.Policy) {
			hostGrant(p).RequireMFA = true
		}, true},
		{"authenticator now required, one enrolled", nil, func(_ *testing.T, r *terminalRig, p *policy.Policy) {
			hostGrant(p).RequireMFA = true
			r.mfa = true
		}, false},
		{"clipboard turned off", func(p *policy.Policy) { hostGrant(p).AllowClipboard = true }, func(_ *testing.T, _ *terminalRig, p *policy.Policy) {
			hostGrant(p).AllowClipboard = false
		}, true},
		{"file transfer turned off", func(p *policy.Policy) { hostGrant(p).AllowFileTransfer = true }, func(_ *testing.T, _ *terminalRig, p *policy.Policy) {
			hostGrant(p).AllowFileTransfer = false
		}, true},
		{"a window shut now", nil, func(_ *testing.T, _ *terminalRig, p *policy.Policy) {
			hostGrant(p).TimeWindows = []policy.TimeWindow{windowAround(time.Now().Add(12 * time.Hour))}
		}, false},
		{"idle and maximum shortened", nil, func(_ *testing.T, _ *terminalRig, p *policy.Policy) {
			g, one := hostGrant(p), 1
			g.IdleTimeoutMinutes, g.MaxSessionMinutes = 1, &one
		}, false},
		{"still granted", nil, func(_ *testing.T, r *terminalRig, p *policy.Policy) {
			g := hostGrant(p)
			g.IdleTimeoutMinutes = 30
			g.Tags = nil
			g.Targets = []policy.GrantTarget{{ID: r.targetID, Protocols: []string{"ssh", "vnc"}}}
			g.TimeWindows = []policy.TimeWindow{windowAround(time.Now())}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port, fp := shellTarget(t)
			r := newTerminalRig(t, port, fp)
			ctx := revokeCtx(t)
			load := func() *policy.Policy {
				p, err := r.h.Policies.Get(r.ctx, r.policyIDs["test-all"])
				if err != nil {
					t.Fatal(err)
				}
				return p
			}
			if tc.before != nil {
				p := load()
				tc.before(p)
				if err := r.h.Policies.Update(r.ctx, p); err != nil {
					t.Fatal(err)
				}
			}
			id := r.liveShell(t, ctx)
			p := load()
			tc.edit(t, r, p)
			if err := r.h.Policies.Update(r.ctx, p); err != nil {
				t.Fatal(err)
			}
			n := r.h.Recheck(r.ctx, []string{r.alice.ID})
			if !tc.ends {
				if n != 0 {
					t.Fatalf("Recheck ended %d session(s), want none", n)
				}
				r.stillLive(t, id)
				return
			}
			if n != 1 {
				t.Fatalf("Recheck ended %d session(s), want 1", n)
			}
			r.revoked(t, id)
		})
	}
}

// TestRecheckAnotherPolicyKeepsTheSession (ADR 0036): a session is judged by
// all of alice's access, not by the policy that admitted it. With a policy
// naming her directly over the same target, leaving the group and deleting
// it end nothing.
func TestRecheckAnotherPolicyKeepsTheSession(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx := revokeCtx(t)
	direct := policytest.Policy("alice-direct", []policy.Subject{policytest.User(r.alice.ID)},
		policytest.Tagged(protocol.KindHost, map[string]string{"env": "test"}, "ssh"))
	if err := r.h.Policies.Create(r.ctx, direct); err != nil {
		t.Fatal(err)
	}
	id := r.liveShell(t, ctx)
	if err := r.groups.RemoveMember(r.ctx, r.opsID, r.alice.ID); err != nil {
		t.Fatal(err)
	}
	if n := r.h.Recheck(r.ctx, []string{r.alice.ID}); n != 0 {
		t.Fatalf("Recheck after leaving the group ended %d session(s), want none", n)
	}
	if _, err := r.groups.Delete(r.ctx, r.opsID); err != nil {
		t.Fatal(err)
	}
	if n := r.h.Recheck(r.ctx, []string{r.alice.ID}); n != 0 {
		t.Fatalf("Recheck after deleting the group ended %d session(s), want none", n)
	}
	r.stillLive(t, id)
}

// TestRecheckANewPolicyCanTighten (ADR 0036): of the grants that admit a
// session, the clipboard is allowed only if every one allows it, so adding a
// policy whose grant has it off, while alice runs with it on, ends that
// session. Adding never loosens; it can tighten.
func TestRecheckANewPolicyCanTighten(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx := revokeCtx(t)
	p, err := r.h.Policies.Get(r.ctx, r.policyIDs["test-all"])
	if err != nil {
		t.Fatal(err)
	}
	hostGrant(p).AllowClipboard = true
	if err := r.h.Policies.Update(r.ctx, p); err != nil {
		t.Fatal(err)
	}
	id := r.liveShell(t, ctx)
	if l, _ := r.h.Registry.Get(id); !l.AllowClipboard {
		t.Fatal("the session does not record its clipboard switch")
	}
	strict := policytest.Policy("no-clipboard", []policy.Subject{policytest.User(r.alice.ID)},
		policytest.Tagged(protocol.KindHost, map[string]string{"env": "test"}, "ssh"))
	if err := r.h.Policies.Create(r.ctx, strict); err != nil {
		t.Fatal(err)
	}
	if n := r.h.Recheck(r.ctx, []string{r.alice.ID}); n != 1 {
		t.Fatalf("Recheck ended %d session(s), want 1", n)
	}
	r.revoked(t, id)
}

// TestRevokeUserEndsEverySession: when alice's account changes (disabled,
// locked, deleted, new roles, signed out everywhere) every live session of
// hers ends as admin_terminated, and nobody else's does.
func TestRevokeUserEndsEverySession(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	ctx := revokeCtx(t)
	first, second := r.liveShell(t, ctx), r.liveShell(t, ctx)
	other := r.bystander(t, r.policyIDs["test-all"])
	if n := r.h.UserRevoked(r.alice.ID); n != 2 {
		t.Fatalf("UserRevoked ended %d session(s), want 2", n)
	}
	for _, id := range []string{first, second} {
		if row, audited := r.endedWith(t, id); row != session.EndAdminTerminated || audited != session.EndAdminTerminated {
			t.Fatalf("session %s ended %q (session.end says %q), want %q", id, row, audited, session.EndAdminTerminated)
		}
	}
	if other.Err() != nil {
		t.Fatal("another user's session was ended")
	}
}

// TestRevokeReachesDesktopAndWinRM: the desktop and WinRM bridges register
// their sessions under the admitting policy too, so deleting it ends them as
// policy_revoked. (The database bridge registers the same way; its end to end
// test needs Docker.)
func TestRevokeReachesDesktopAndWinRM(t *testing.T) {
	t.Run("desktop", func(t *testing.T) {
		r := newDesktopRig(t)
		ctx := revokeCtx(t)
		tg := r.addTarget(t, "vnc-box", map[target.Protocol]int{target.VNC: 5900}, "")
		ws, _, err := r.dial(ctx, r.ticket(t, tg, "vnc")) //nolint:bodyclose // the library closes the handshake body
		if err != nil {
			t.Fatal(err)
		}
		defer ws.CloseNow()
		_, first, err := ws.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		id := sessionIDFrom(string(first))
		desk := r.policyIDs["desk"]
		r.waitLive(t, id, desk)
		if err := r.h.Policies.Delete(r.ctx, desk); err != nil {
			t.Fatal(err)
		}
		if n := r.h.Recheck(r.ctx, []string{r.alice.ID}); n != 1 {
			t.Fatalf("Recheck ended %d session(s), want 1", n)
		}
		r.revoked(t, id)
	})
	t.Run("winrm", func(t *testing.T) {
		r := newWinRMRig(t)
		ctx := revokeCtx(t)
		tg := r.winTarget(t, "win-1", "admin", r.wsm.Fingerprint())
		ws, _, err := r.open(t, tg) //nolint:bodyclose // the library closes the handshake body
		if err != nil {
			t.Fatal(err)
		}
		defer ws.CloseNow()
		var id string
		for id == "" {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var c termFrame
			if typ == websocket.MessageText && json.Unmarshal(data, &c) == nil && c.T == "ready" {
				id = c.SessionID
			}
		}
		testAll := r.policyIDs["test-all"]
		r.waitLive(t, id, testAll)
		if err := r.h.Policies.Delete(r.ctx, testAll); err != nil {
			t.Fatal(err)
		}
		if n := r.h.Recheck(r.ctx, []string{r.alice.ID}); n != 1 {
			t.Fatalf("Recheck ended %d session(s), want 1", n)
		}
		r.revoked(t, id)
	})
}

// waitLive waits for a session to enter the registry and checks the policy
// it was registered under.
func (f *connectFixture) waitLive(t *testing.T, sessionID, policyID string) {
	t.Helper()
	for range 250 {
		if l, ok := f.h.Registry.Get(sessionID); ok {
			if l.PolicyID != policyID {
				t.Fatalf("live session %s carries policy %q, want %q", sessionID, l.PolicyID, policyID)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("session %q never went live", sessionID)
}
