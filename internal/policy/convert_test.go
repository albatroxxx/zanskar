// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/protocol"
)

// The conversion oracle (ADR 0036): for every target of a synthetic
// inventory, every protocol it can serve and instants inside and outside the
// windows, the frozen legacy evaluator over the legacy policies and the new
// evaluator over their conversion must agree.

var oracleTargets = []TargetRef{
	{Kind: protocol.KindHost, ID: "h-prod", Tags: map[string]string{"env": "prod", "tier": "web"}},
	{Kind: protocol.KindHost, ID: "h-win", Tags: map[string]string{"env": "prod", "os": "windows"}},
	{Kind: protocol.KindHost, ID: "h-stage", Tags: map[string]string{"env": "staging", "tier": "web"}},
	{Kind: protocol.KindHost, ID: "h-bare"},
	{Kind: protocol.KindDatabase, ID: "db-prod", Tags: map[string]string{"env": "prod"}},
	{Kind: protocol.KindApplication, ID: "app-wiki", Tags: map[string]string{"env": "prod", "team": "docs"}},
	{Kind: protocol.KindAutoscaling, ASGID: "asg-web", Tags: map[string]string{"env": "prod", "tier": "web"}},
	{Kind: protocol.KindAutoscaling, ASGID: "asg-bare"},
}

var oracleInventory = legacyInventory{
	targetKind: map[string]string{"h-prod": protocol.KindHost, "h-win": protocol.KindHost, "h-stage": protocol.KindHost, "h-bare": protocol.KindHost,
		"db-prod": protocol.KindDatabase, "app-wiki": protocol.KindApplication},
	asgs: map[string]bool{"asg-web": true, "asg-bare": true},
}

var allProtocols = []string{"ssh", "rdp", "vnc", "winrm", "database", "http"}

// office is weekdays 09:00-18:00 UTC; the instants fall inside and outside.
var office = []TimeWindow{{Days: []string{"mon", "tue", "wed", "thu", "fri"}, From: "09:00", To: "18:00", TZ: "UTC"}}

var oracleInstants = []time.Time{
	time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC), // Wednesday morning: open
	time.Date(2026, 10, 28, 20, 0, 0, 0, time.UTC), // Wednesday evening: shut
	time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC), // Saturday: shut
}

// oracleShapes is one legacy policy of every shape the old form could make.
func oracleShapes() []*legacyPolicy {
	sel := func(ids, asgs []string, tags map[string]string) legacySelector {
		return legacySelector{Targets: ids, ASGs: asgs, Tags: tags}
	}
	return []*legacyPolicy{
		{ID: "tags-many-kinds", Name: "tags-many-kinds", Enabled: true, GroupID: "g", Selector: sel(nil, nil, map[string]string{"env": "prod"}),
			Protocols: []string{"ssh", "rdp", "database", "http"}, IdleTimeoutMinutes: 15, RequireMFA: true},
		{ID: "ids-with-gone", Name: "ids-with-gone", Enabled: true, UserID: "u", Selector: sel([]string{"h-bare", "db-prod", "gone"}, nil, nil),
			Protocols: []string{"ssh", "database"}, IdleTimeoutMinutes: 20, AllowFileTransfer: true},
		{ID: "a-host-for-database-only", Name: "a-host-for-database-only", Enabled: true, GroupID: "g", Selector: sel([]string{"h-bare"}, nil, nil),
			Protocols: []string{"database"}, IdleTimeoutMinutes: 15},
		{ID: "fleet-approval", Name: "fleet-approval", Enabled: true, GroupID: "g", Selector: sel(nil, []string{"asg-web", "gone-asg"}, nil),
			Protocols: []string{"ssh", "vnc"}, IdleTimeoutMinutes: 10, RequireApproval: true, MaxSessionMinutes: intp(60)},
		{ID: "rules-only", Name: "rules-only", Enabled: true, GroupID: "g", IdleTimeoutMinutes: 25, AllowClipboard: true, RetentionDays: intp(90),
			Rules: []legacyRule{
				{Selector: sel(nil, nil, map[string]string{"tier": "web"}), Protocols: []string{"ssh"}},
				{Selector: sel([]string{"app-wiki"}, nil, nil), Protocols: []string{"http"}},
				{Selector: sel(nil, []string{"asg-web", "asg-bare"}, nil), Protocols: []string{"rdp"}},
			}},
		{ID: "base-and-rule-same-target", Name: "base-and-rule-same-target", Enabled: true, UserID: "u", Selector: sel([]string{"h-prod"}, nil, nil),
			Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15, Rules: []legacyRule{
				{Selector: sel([]string{"h-prod", "h-win"}, nil, nil), Protocols: []string{"rdp", "winrm"}},
				{Selector: sel(nil, nil, map[string]string{"env": "prod"}), Protocols: []string{"ssh"}},
			}},
		{ID: "ids-and-tags", Name: "ids-and-tags", Enabled: true, GroupID: "g", Selector: sel([]string{"h-bare"}, []string{"asg-bare"}, map[string]string{"env": "staging", "tier": "web"}),
			Protocols: []string{"ssh", "vnc", "winrm"}, IdleTimeoutMinutes: 15},
		{ID: "office-hours", Name: "office-hours", Enabled: true, GroupID: "g", Selector: sel(nil, nil, map[string]string{"env": "prod"}),
			Protocols: []string{"ssh", "database"}, TimeWindows: office, IdleTimeoutMinutes: 5, MaxSessionMinutes: intp(120), AllowClipboard: true, RetentionDays: intp(30)},
		{ID: "disabled", Name: "disabled", Enabled: false, GroupID: "g", Selector: sel(nil, nil, map[string]string{"env": "staging"}),
			Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15},
		{ID: "nothing-left", Name: "nothing-left", Enabled: true, GroupID: "g", Selector: sel([]string{"gone"}, nil, nil),
			Protocols: []string{"ssh"}, IdleTimeoutMinutes: 15},
	}
}

// converted runs convert on each legacy policy into a new one.
func converted(t testing.TB, legacy []*legacyPolicy) []*Policy {
	t.Helper()
	n := 0
	out := make([]*Policy, 0, len(legacy))
	for _, l := range legacy {
		subjects, grants, _ := convert(l, oracleInventory, func() string { n++; return fmt.Sprintf("g%d", n) })
		p := &Policy{ID: l.ID, Name: l.Name, Enabled: l.Enabled, Subjects: subjects, Grants: grants}
		if len(grants) > 0 {
			if err := p.Validate(); err != nil {
				t.Fatalf("%s converts to an invalid policy: %v", l.Name, err)
			}
		}
		out = append(out, p)
	}
	return out
}

// servable reports whether the target can serve the protocol at all; the
// legacy evaluator, blind to kinds, said yes to ssh on a database.
func servableOn(ref TargetRef, proto string) bool { return protocol.KindServes(ref.Kind, proto) }

// compare checks one evaluation: Allowed and RequireApproval always equal;
// every term equal when exactly one policy admits; otherwise each new term
// at least as strict as the legacy one.
func compare(t testing.TB, what string, legacy []*legacyPolicy, current []*Policy, ref TargetRef, proto string, at time.Time) {
	t.Helper()
	old := legacyEvaluate(legacy, ref, proto, at)
	cur := Evaluate(current, ref, proto, at)
	if !servableOn(ref, proto) {
		if cur.Allowed {
			t.Fatalf("%s: %s on a %s (%s) allowed", what, proto, ref.Kind, ref.ID+ref.ASGID)
		}
		return
	}
	where := fmt.Sprintf("%s: %s on %s at %s", what, proto, ref.ID+ref.ASGID, at.Format("Mon 15:04"))
	if old.Allowed != cur.Allowed || old.RequireApproval != cur.RequireApproval {
		t.Fatalf("%s: legacy allowed %v approval %v, now %v %v (%s)", where, old.Allowed, old.RequireApproval, cur.Allowed, cur.RequireApproval, cur.Reason)
	}
	if !old.Allowed {
		return
	}
	admitting := map[string]bool{}
	for _, g := range cur.Grants {
		admitting[g.PolicyID] = true
	}
	if len(admitting) == 1 {
		if old.IdleTimeout != cur.IdleTimeout || old.MaxSession != cur.MaxSession || old.AllowClipboard != cur.AllowClipboard ||
			old.AllowFileTransfer != cur.AllowFileTransfer || old.RequireMFA != cur.RequireMFA || old.RetentionDays != cur.RetentionDays {
			t.Fatalf("%s: one policy admits, terms differ:\nlegacy %+v\nnow    %+v", where, old, cur)
		}
		return
	}
	switch {
	case cur.IdleTimeout > old.IdleTimeout:
		t.Fatalf("%s: idle looser, %v over %v", where, cur.IdleTimeout, old.IdleTimeout)
	case old.MaxSession > 0 && (cur.MaxSession == 0 || cur.MaxSession > old.MaxSession):
		t.Fatalf("%s: maximum looser, %v over %v", where, cur.MaxSession, old.MaxSession)
	case cur.AllowClipboard && !old.AllowClipboard, cur.AllowFileTransfer && !old.AllowFileTransfer:
		t.Fatalf("%s: a switch on that was off", where)
	case old.RequireMFA && !cur.RequireMFA:
		t.Fatalf("%s: authenticator no longer required", where)
	case cur.RetentionDays < old.RetentionDays:
		t.Fatalf("%s: retention shorter", where)
	}
}

// TestConvertEachShapeAlone: each legacy shape, converted on its own, grants
// exactly what it granted, under exactly its conditions.
func TestConvertEachShapeAlone(t *testing.T) {
	for _, l := range oracleShapes() {
		current := converted(t, []*legacyPolicy{l})
		for _, ref := range oracleTargets {
			for _, proto := range allProtocols {
				for _, at := range oracleInstants {
					compare(t, l.Name, []*legacyPolicy{l}, current, ref, proto, at)
				}
			}
		}
	}
}

// TestConvertAllShapesTogether: with every shape at once, one person's
// access is the same, and where several policies admit, each term is at
// least as strict as before (the overlap rule ADR 0036 changes on purpose).
func TestConvertAllShapesTogether(t *testing.T) {
	legacy := oracleShapes()
	current := converted(t, legacy)
	for _, ref := range oracleTargets {
		for _, proto := range allProtocols {
			for _, at := range oracleInstants {
				compare(t, "all", legacy, current, ref, proto, at)
			}
		}
	}
}

// TestConvertShapes pins what the conversion writes for the shapes a reader
// cares about: kinds split, ids merged, gone ids named, conditions copied.
func TestConvertShapes(t *testing.T) {
	byName := map[string]*legacyPolicy{}
	for _, l := range oracleShapes() {
		byName[l.Name] = l
	}
	n := 0
	id := func() string { n++; return fmt.Sprintf("g%d", n) }

	subjects, grants, dropped := convert(byName["tags-many-kinds"], oracleInventory, id)
	if len(subjects) != 1 || subjects[0] != (Subject{Kind: SubjectGroup, ID: "g"}) {
		t.Fatalf("subjects %v", subjects)
	}
	kinds := []string{}
	for _, g := range grants {
		kinds = append(kinds, g.Kind+":"+strings.Join(g.Tags.Protocols, ","))
		if !g.RequireMFA || g.Tags.Match["env"][0] != "prod" || len(g.Targets) != 0 {
			t.Fatalf("tag grant %+v", g)
		}
	}
	if want := []string{"host:ssh,rdp", "database:database", "application:http", "autoscaling:ssh,rdp"}; !slices.Equal(kinds, want) || len(dropped) != 0 {
		t.Fatalf("a tag selector over four kinds: %v (dropped %v), want %v", kinds, dropped, want)
	}

	// The named targets merge into one host grant; the rule's env=prod tag
	// reaches hosts and autoscaling groups over ssh, a grant for each.
	_, grants, dropped = convert(byName["base-and-rule-same-target"], oracleInventory, id)
	if len(grants) != 3 || grants[1].Tags == nil || grants[2].Kind != protocol.KindAutoscaling || grants[0].Kind != protocol.KindHost || len(grants[0].Targets) != 2 ||
		!slices.Equal(grants[0].Targets[0].Protocols, []string{"ssh", "rdp", "winrm"}) || grants[0].Targets[0].ID != "h-prod" {
		t.Fatalf("a target named by the base and a rule: %+v", grants)
	}
	if len(dropped) != 0 {
		t.Fatalf("dropped %v", dropped)
	}

	_, grants, dropped = convert(byName["a-host-for-database-only"], oracleInventory, id)
	if len(grants) != 0 || len(dropped) != 1 || !strings.Contains(dropped[0], "h-bare (a host serves none of database)") {
		t.Fatalf("a host named for database only: grants %+v, dropped %v", grants, dropped)
	}

	_, grants, dropped = convert(byName["fleet-approval"], oracleInventory, id)
	if len(grants) != 1 || grants[0].Access != AccessApproval || *grants[0].MaxSessionMinutes != 60 || len(dropped) != 1 || !strings.HasPrefix(dropped[0], "gone-asg") {
		t.Fatalf("an approval fleet with a gone group: %+v, dropped %v", grants, dropped)
	}

	_, grants, _ = convert(byName["nothing-left"], oracleInventory, id)
	if len(grants) != 0 {
		t.Fatalf("a policy naming only a gone target kept grants: %+v", grants)
	}
}

// FuzzConvert: random legacy policies over the inventory keep their access
// through the conversion, alone and together.
func FuzzConvert(f *testing.F) {
	for _, seed := range []uint64{1, 2, 3, 42, 2026} {
		f.Add(seed)
	}
	ids := []string{"h-prod", "h-win", "h-stage", "h-bare", "db-prod", "app-wiki", "gone"}
	asgs := []string{"asg-web", "asg-bare", "gone-asg"}
	tagSets := []map[string]string{nil, {"env": "prod"}, {"env": "staging"}, {"tier": "web"}, {"env": "prod", "tier": "web"}, {"team": "docs"}}
	f.Fuzz(func(t *testing.T, seed uint64) {
		r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
		pick := func(from []string) []string {
			var out []string
			for _, s := range from {
				if r.IntN(3) == 0 {
					out = append(out, s)
				}
			}
			return out
		}
		selector := func() legacySelector {
			return legacySelector{Targets: pick(ids), ASGs: pick(asgs), Tags: tagSets[r.IntN(len(tagSets))]}
		}
		var legacy []*legacyPolicy
		for i := range 1 + r.IntN(4) {
			l := &legacyPolicy{ID: fmt.Sprintf("p%d", i), Name: fmt.Sprintf("p%d", i), Enabled: r.IntN(5) != 0, GroupID: "g",
				IdleTimeoutMinutes: 1 + r.IntN(60), RequireMFA: r.IntN(2) == 0, AllowClipboard: r.IntN(2) == 0,
				AllowFileTransfer: r.IntN(2) == 0, RequireApproval: r.IntN(3) == 0}
			if r.IntN(2) == 0 {
				l.MaxSessionMinutes = intp(1 + r.IntN(600))
			}
			if r.IntN(2) == 0 {
				l.RetentionDays = intp(1 + r.IntN(365))
			}
			if r.IntN(3) == 0 {
				l.TimeWindows = office
			}
			if r.IntN(4) != 0 {
				l.Selector, l.Protocols = selector(), pick(allProtocols)
				if l.Selector.empty() || len(l.Protocols) == 0 {
					l.Selector, l.Protocols = legacySelector{}, nil
				}
			}
			for range r.IntN(3) {
				if s, p := selector(), pick(allProtocols); !s.empty() && len(p) > 0 {
					l.Rules = append(l.Rules, legacyRule{Selector: s, Protocols: p})
				}
			}
			legacy = append(legacy, l)
		}
		for _, l := range legacy {
			alone := converted(t, []*legacyPolicy{l})
			for _, ref := range oracleTargets {
				for _, proto := range allProtocols {
					for _, at := range oracleInstants {
						compare(t, l.Name, []*legacyPolicy{l}, alone, ref, proto, at)
					}
				}
			}
		}
		together := converted(t, legacy)
		for _, ref := range oracleTargets {
			for _, proto := range allProtocols {
				for _, at := range oracleInstants {
					compare(t, "together", legacy, together, ref, proto, at)
				}
			}
		}
	})
}
