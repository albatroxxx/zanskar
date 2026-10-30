// SPDX-License-Identifier: Apache-2.0

// Package policytest builds access policies for tests in other packages, so
// a fixture reads as what it grants: who, on what, over which protocols.
// Conditions take the zero values a test would otherwise write out (no
// authenticator required, clipboard and file transfer off, standing access);
// set fields on the returned grant for anything else.
package policytest

import "github.com/albatroxxx/zanskar/internal/policy"

// Group and User name a policy's subjects.
func Group(id string) policy.Subject { return policy.Subject{Kind: policy.SubjectGroup, ID: id} }

// User names a user subject.
func User(id string) policy.Subject { return policy.Subject{Kind: policy.SubjectUser, ID: id} }

// Named grants protos on each of ids, all of kind.
func Named(kind string, ids []string, protos ...string) policy.Grant {
	g := policy.Grant{Kind: kind, IdleTimeoutMinutes: 15}
	for _, id := range ids {
		g.Targets = append(g.Targets, policy.GrantTarget{ID: id, Protocols: append([]string(nil), protos...)})
	}
	return g
}

// Tagged grants protos on every target of kind carrying every tag.
func Tagged(kind string, tags map[string]string, protos ...string) policy.Grant {
	match := map[string][]string{}
	for k, v := range tags {
		match[k] = []string{v}
	}
	return policy.Grant{Kind: kind, IdleTimeoutMinutes: 15, Tags: &policy.TagMatch{Match: match, Protocols: append([]string(nil), protos...)}}
}

// Policy is an enabled policy with the subjects and grants given.
func Policy(name string, subjects []policy.Subject, grants ...policy.Grant) *policy.Policy {
	return &policy.Policy{Name: name, Enabled: true, Subjects: subjects, Grants: grants}
}

// Approval makes g an approval grant, capped at max minutes when max > 0.
func Approval(g policy.Grant, max int) policy.Grant {
	g.Access = policy.AccessApproval
	if max > 0 {
		g.MaxSessionMinutes = &max
	}
	return g
}
