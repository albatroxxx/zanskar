// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/protocol"
)

func intp(v int) *int { return &v }

func hostGrant(ids ...string) Grant {
	g := Grant{Kind: protocol.KindHost}
	for _, id := range ids {
		g.Targets = append(g.Targets, GrantTarget{ID: id, Protocols: []string{"ssh"}})
	}
	return g
}

func valid(grants ...Grant) *Policy {
	return &Policy{Name: "p", Enabled: true, Subjects: []Subject{{Kind: SubjectGroup, ID: "g1"}}, Grants: grants}
}

// TestValidate (ADR 0036): a policy names at least one group or user and
// holds at least one grant; a grant names a kind, targets or tags, and only
// protocols that kind serves. Defaults fill what a grant leaves out.
func TestValidate(t *testing.T) {
	p := valid(hostGrant("t1"))
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	g := p.Grants[0]
	if g.Access != AccessStanding || g.SignIn != SignInTarget || g.IdleTimeoutMinutes != 15 || g.TimeWindows == nil {
		t.Fatalf("defaults not filled: %+v", g)
	}

	tags := func(m map[string][]string, protos ...string) *TagMatch { return &TagMatch{Match: m, Protocols: protos} }
	cases := []struct {
		name string
		edit func(p *Policy)
		want string
	}{
		{"no name", func(p *Policy) { p.Name = " " }, "name must be"},
		{"no subject", func(p *Policy) { p.Subjects = nil }, "at least one group or user"},
		{"a subject twice", func(p *Policy) { p.Subjects = append(p.Subjects, p.Subjects[0]) }, "named twice"},
		{"a subject of no kind", func(p *Policy) { p.Subjects = []Subject{{Kind: "team", ID: "x"}} }, "a group or a user"},
		{"no grant", func(p *Policy) { p.Grants = nil }, "at least one grant"},
		{"no kind", func(p *Policy) { p.Grants[0].Kind = "vm" }, "kind must be"},
		{"nothing named", func(p *Policy) { p.Grants[0].Targets = nil }, "name targets or match tags"},
		{"a target twice", func(p *Policy) { p.Grants[0] = hostGrant("t1", "t1") }, "named twice"},
		{"a target with no protocol", func(p *Policy) { p.Grants[0].Targets[0].Protocols = nil }, "at least one protocol"},
		{"ssh on a database", func(p *Policy) {
			p.Grants[0] = Grant{Kind: protocol.KindDatabase, Targets: []GrantTarget{{ID: "d1", Protocols: []string{"ssh"}}}}
		}, `a database does not serve "ssh"`},
		{"database on a host", func(p *Policy) { p.Grants[0].Targets[0].Protocols = []string{"database"} }, `a host does not serve "database"`},
		{"a protocol twice", func(p *Policy) { p.Grants[0].Targets[0].Protocols = []string{"ssh", "ssh"} }, "given twice"},
		{"tags with no key", func(p *Policy) { p.Grants[0].Tags = tags(map[string][]string{}, "ssh") }, "at least one key"},
		{"a tag with no value", func(p *Policy) { p.Grants[0].Tags = tags(map[string][]string{"env": {}}, "ssh") }, "needs 1-16 values"},
		{"an empty tag value", func(p *Policy) { p.Grants[0].Tags = tags(map[string][]string{"env": {""}}, "ssh") }, "values are 1-64"},
		{"a tag value twice", func(p *Policy) { p.Grants[0].Tags = tags(map[string][]string{"env": {"a", "a"}}, "ssh") }, "given twice"},
		{"tags with no protocol", func(p *Policy) { p.Grants[0].Tags = tags(map[string][]string{"env": {"a"}}) }, "at least one protocol"},
		{"an unknown access", func(p *Policy) { p.Grants[0].Access = "sometimes" }, "standing or approval"},
		{"an unknown sign-in", func(p *Policy) { p.Grants[0].SignIn = "theirs" }, "target or own"},
		{"own login on an application", func(p *Policy) {
			p.Grants[0] = Grant{Kind: protocol.KindApplication, Targets: []GrantTarget{{ID: "a1", Protocols: []string{"http"}}}, SignIn: SignInOwn}
		}, "no login of its own"},
		{"idle over a day", func(p *Policy) { p.Grants[0].IdleTimeoutMinutes = 1441 }, "idle_timeout_minutes"},
		{"a zero maximum", func(p *Policy) { p.Grants[0].MaxSessionMinutes = intp(0) }, "max_session_minutes"},
		{"retention over ten years", func(p *Policy) { p.Grants[0].RetentionDays = intp(3651) }, "retention_days"},
		{"a bad window", func(p *Policy) {
			p.Grants[0].TimeWindows = []TimeWindow{{Days: []string{"mon"}, From: "9am", To: "18:00"}}
		}, "HH:MM"},
		{"two grants, one id", func(p *Policy) {
			p.Grants = []Grant{hostGrant("t1"), hostGrant("t2")}
			p.Grants[0].ID, p.Grants[1].ID = "same", "same"
		}, "repeats grant id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := valid(hostGrant("t1"))
			c.edit(p)
			err := p.Validate()
			if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an invalid input naming %q", err, c.want)
			}
		})
	}
}

// TestCovers (ADR 0036): a grant covers its own kind only; a named target
// with the protocol, or a tag rule where every key is present with one of
// its values. An autoscaling grant names groups.
func TestCovers(t *testing.T) {
	g := Grant{Kind: protocol.KindHost,
		Targets: []GrantTarget{{ID: "t1", Protocols: []string{"ssh", "rdp"}}},
		Tags:    &TagMatch{Match: map[string][]string{"env": {"prod", "staging"}, "tier": {"web"}}, Protocols: []string{"ssh"}}}
	host := func(id string, tags map[string]string) TargetRef {
		return TargetRef{Kind: protocol.KindHost, ID: id, Tags: tags}
	}
	cases := []struct {
		name  string
		ref   TargetRef
		proto string
		want  bool
	}{
		{"named, granted protocol", host("t1", nil), "rdp", true},
		{"named, protocol not granted", host("t1", nil), "vnc", false},
		{"tags: every key, one of the values", host("t2", map[string]string{"env": "staging", "tier": "web"}), "ssh", true},
		{"tags: a key missing", host("t2", map[string]string{"env": "prod"}), "ssh", false},
		{"tags: a value not listed", host("t2", map[string]string{"env": "dev", "tier": "web"}), "ssh", false},
		{"tags: a protocol the rule does not grant", host("t2", map[string]string{"env": "prod", "tier": "web"}), "rdp", false},
		{"another kind with the same id and tags", TargetRef{Kind: protocol.KindDatabase, ID: "t1", Tags: map[string]string{"env": "prod", "tier": "web"}}, "ssh", false},
	}
	for _, c := range cases {
		if got := g.Covers(c.ref, c.proto); got != c.want {
			t.Errorf("%s: Covers = %v", c.name, got)
		}
	}
	fleet := Grant{Kind: protocol.KindAutoscaling, Targets: []GrantTarget{{ID: "g1", Protocols: []string{"ssh"}}}}
	if !fleet.Covers(TargetRef{Kind: protocol.KindAutoscaling, ASGID: "g1"}, "ssh") {
		t.Error("an autoscaling grant does not cover its group")
	}
	if fleet.Covers(TargetRef{Kind: protocol.KindAutoscaling, ID: "g1"}, "ssh") {
		t.Error("an autoscaling grant matched a target id, not a group id")
	}
}

// TestEvaluateOverlap (ADR 0036): standing access wins over approval; of the
// grants that let you in, each limit is the strictest.
func TestEvaluateOverlap(t *testing.T) {
	ref := TargetRef{Kind: protocol.KindHost, ID: "t1"}
	grant := func(idle int, edit func(*Grant)) Grant {
		g := hostGrant("t1")
		g.IdleTimeoutMinutes, g.Access, g.SignIn = idle, AccessStanding, SignInTarget
		if edit != nil {
			edit(&g)
		}
		return g
	}
	pol := func(name string, gs ...Grant) *Policy {
		p := valid(gs...)
		p.Name, p.ID = name, "id-"+name
		for i := range p.Grants {
			p.Grants[i].ID = name + "-" + string(rune('a'+i))
		}
		return p
	}
	now := time.Now()

	// Two standing grants: every term the strictest of the two.
	loose := pol("a-loose", grant(10, func(g *Grant) {
		g.AllowClipboard, g.AllowFileTransfer, g.RetentionDays = true, true, intp(30)
	}))
	strict := pol("b-strict", grant(30, func(g *Grant) {
		g.RequireMFA, g.AllowClipboard, g.AllowFileTransfer, g.MaxSessionMinutes, g.RetentionDays = true, false, true, intp(60), intp(90)
	}))
	d := Evaluate([]*Policy{loose, strict}, ref, "ssh", now)
	switch {
	case !d.Allowed || d.RequireApproval:
		t.Fatalf("not allowed standing: %+v", d)
	case d.IdleTimeout != 10*time.Minute:
		t.Errorf("idle %v, want the shortest", d.IdleTimeout)
	case d.MaxSession != 60*time.Minute:
		t.Errorf("maximum %v, want the one set, as none loses to any limit", d.MaxSession)
	case d.AllowClipboard:
		t.Error("clipboard allowed though one grant forbids it")
	case !d.AllowFileTransfer:
		t.Error("file transfer refused though every grant allows it")
	case !d.RequireMFA:
		t.Error("no authenticator required though one grant requires it")
	case d.RetentionDays != 90:
		t.Errorf("retention %d, want the longest", d.RetentionDays)
	case d.Policy != loose || d.GrantID != "a-loose-a" || len(d.Grants) != 2:
		t.Errorf("deciding grant %s/%s of %v, want the shortest idle", d.Policy.Name, d.GrantID, d.Grants)
	}

	// Standing beats approval, which lends nothing.
	gated := pol("c-gated", grant(5, func(g *Grant) { g.Access, g.AllowClipboard = AccessApproval, true }))
	if d := Evaluate([]*Policy{gated, loose}, ref, "ssh", now); d.RequireApproval || d.IdleTimeout != 10*time.Minute || !d.AllowClipboard || len(d.Grants) != 1 {
		t.Errorf("an approval grant lent its terms to standing access: %+v", d)
	}
	if d := Evaluate([]*Policy{gated}, ref, "ssh", now); !d.Allowed || !d.RequireApproval {
		t.Errorf("only an approval grant: %+v", d)
	}

	// Ties go to the policy first by name, then the grant first in it.
	twin := pol("d-twin", grant(10, nil), grant(10, nil))
	if d := Evaluate([]*Policy{loose, twin}, ref, "ssh", now); d.Policy != loose {
		t.Errorf("tie went to %s", d.Policy.Name)
	}
	if d := Evaluate([]*Policy{twin}, ref, "ssh", now); d.GrantID != "d-twin-a" {
		t.Errorf("tie went to grant %s", d.GrantID)
	}

	// Sign-in options gather across the deciding grants.
	own := pol("e-own", grant(15, func(g *Grant) { g.SignIn = SignInOwn }))
	if d := Evaluate([]*Policy{own}, ref, "ssh", now); d.SignInTarget || !d.SignInOwn {
		t.Errorf("own only: %+v", d)
	}
	if d := Evaluate([]*Policy{own, loose}, ref, "ssh", now); !d.SignInTarget || !d.SignInOwn {
		t.Errorf("both: %+v", d)
	}
}

// TestEvaluateRefusals: what is denied says why; a disabled policy grants
// nothing; a shut window is a filter, and EvaluateLive, for a running
// session, does not apply it.
func TestEvaluateRefusals(t *testing.T) {
	ref := TargetRef{Kind: protocol.KindHost, ID: "t1"}
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC) // a Friday
	p := valid(hostGrant("t1"))
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if d := Evaluate(nil, ref, "ssh", now); d.Allowed || d.Reason != "no policy grants access to this target" {
		t.Errorf("no policies: %+v", d)
	}
	if d := Evaluate([]*Policy{p}, ref, "rdp", now); d.Allowed || d.Reason != "protocol not allowed by policy" {
		t.Errorf("an uncovered protocol: %+v", d)
	}
	p.Grants[0].TimeWindows = []TimeWindow{{Days: []string{"sat"}, From: "09:00", To: "18:00", TZ: "UTC"}}
	if d := Evaluate([]*Policy{p}, ref, "ssh", now); d.Allowed || d.Reason != "outside the policy's access window" {
		t.Errorf("a shut window: %+v", d)
	}
	if d := EvaluateLive([]*Policy{p}, ref, "ssh", now); !d.Allowed {
		t.Errorf("a running session judged against a shut window: %+v", d)
	}
	p.Enabled = false
	if d := Evaluate([]*Policy{p}, ref, "ssh", now); d.Allowed {
		t.Error("a disabled policy granted access")
	}
}

// TestReferences: a grant naming a target or a group by id is a reference;
// a tag rule is not.
func TestReferences(t *testing.T) {
	p := valid(hostGrant("t1"),
		Grant{Kind: protocol.KindAutoscaling, Targets: []GrantTarget{{ID: "g1", Protocols: []string{"ssh"}}}},
		Grant{Kind: protocol.KindHost, Tags: &TagMatch{Match: map[string][]string{"env": {"prod"}}, Protocols: []string{"ssh"}}})
	if !p.References("t1", "") || !p.References("", "g1") {
		t.Fatal("a named target or group is not a reference")
	}
	if p.References("t2", "") || p.References("", "t1") || p.References("g1", "") {
		t.Fatal("a reference across kinds, or by tag")
	}
}
