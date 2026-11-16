// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func approvalGrant(approvers ...Subject) Grant {
	return Grant{Kind: "host", Targets: []GrantTarget{{ID: "t1", Protocols: []string{"ssh"}}}, Access: AccessApproval, Approvers: approvers}
}

func validateOne(g Grant) error {
	p := &Policy{Name: "p", Subjects: []Subject{{Kind: SubjectUser, ID: "u1"}}, Grants: []Grant{g}}
	return p.Validate()
}

// TestGrantApproversValidation: approvers are for approval grants, each a
// group or a user by id, none twice, at most MaxGrantApprovers (ADR 0049).
func TestGrantApproversValidation(t *testing.T) {
	if err := validateOne(approvalGrant(Subject{Kind: SubjectGroup, ID: "g1"}, Subject{Kind: SubjectUser, ID: "u2"})); err != nil {
		t.Fatalf("two approvers: %v", err)
	}
	standing := approvalGrant(Subject{Kind: SubjectGroup, ID: "g1"})
	standing.Access = AccessStanding
	if err := validateOne(standing); !errors.Is(err, ErrApproversWithoutApproval) || !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("approvers on a standing grant: %v", err)
	}
	if err := validateOne(approvalGrant(Subject{Kind: "team", ID: "g1"})); err == nil || !strings.Contains(err.Error(), "group or a user") {
		t.Fatalf("bad kind: %v", err)
	}
	if err := validateOne(approvalGrant(Subject{Kind: SubjectUser, ID: ""})); err == nil {
		t.Fatal("empty id accepted")
	}
	if err := validateOne(approvalGrant(Subject{Kind: SubjectUser, ID: "u1"}, Subject{Kind: SubjectUser, ID: "u1"})); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("duplicate: %v", err)
	}
	many := make([]Subject, 0, MaxGrantApprovers+1)
	for i := 0; i <= MaxGrantApprovers; i++ {
		many = append(many, Subject{Kind: SubjectUser, ID: fmt.Sprintf("u%d", i)})
	}
	if err := validateOne(approvalGrant(many...)); err == nil || !strings.Contains(err.Error(), "at most 32") {
		t.Fatalf("too many: %v", err)
	}
	// An empty list is kept as none, so a grant written without approvers
	// and one written with [] read the same.
	g := approvalGrant()
	g.Approvers = []Subject{}
	p := &Policy{Name: "p", Subjects: []Subject{{Kind: SubjectUser, ID: "u1"}}, Grants: []Grant{g}}
	if err := p.Validate(); err != nil || p.Grants[0].Approvers != nil {
		t.Fatalf("empty approvers: %v %v", err, p.Grants[0].Approvers)
	}
}

// TestApproversOf: the union over the covering approval grants of enabled
// policies, each subject once in the order first seen; standing grants, a
// grant for another target and a disabled policy count for nothing.
func TestApproversOf(t *testing.T) {
	g1, u2, u3 := Subject{Kind: SubjectGroup, ID: "g1"}, Subject{Kind: SubjectUser, ID: "u2"}, Subject{Kind: SubjectUser, ID: "u3"}
	a := &Policy{Name: "a", Enabled: true, Grants: []Grant{approvalGrant(g1, u2)}}
	other := approvalGrant(u3)
	other.Targets = []GrantTarget{{ID: "t9", Protocols: []string{"ssh"}}}
	b := &Policy{Name: "b", Enabled: true, Grants: []Grant{approvalGrant(u2, u3), other}}
	standing := approvalGrant(Subject{Kind: SubjectUser, ID: "u9"})
	standing.Access = AccessStanding
	c := &Policy{Name: "c", Enabled: true, Grants: []Grant{standing}}
	off := &Policy{Name: "off", Enabled: false, Grants: []Grant{approvalGrant(Subject{Kind: SubjectUser, ID: "u8"})}}
	for _, p := range []*Policy{a, b, c, off} {
		for i := range p.Grants {
			if err := p.Grants[i].validate(); err != nil && !errors.Is(err, ErrApproversWithoutApproval) {
				t.Fatal(err)
			}
		}
	}
	got := ApproversOf([]*Policy{a, b, c, off}, TargetRef{Kind: "host", ID: "t1"}, "ssh")
	want := []Subject{g1, u2, u3}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("approvers: %v, want %v", got, want)
	}
	if got := ApproversOf([]*Policy{c}, TargetRef{Kind: "host", ID: "t1"}, "ssh"); got != nil {
		t.Fatalf("a standing grant names nobody: %v", got)
	}
	// Evaluate is untouched by approvers: the decision is the same.
	d := Evaluate([]*Policy{a}, TargetRef{Kind: "host", ID: "t1"}, "ssh", time.Now())
	if !d.Allowed || !d.RequireApproval {
		t.Fatalf("evaluate: %+v", d)
	}
}
