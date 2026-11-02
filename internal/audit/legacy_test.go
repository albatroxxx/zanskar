// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"strings"
	"testing"
)

// A policy event recorded before 1.15.0 under the object type "policy" is the
// same kind of thing as "access_policy": the facets offer one choice, and a
// filter on it finds both (2026-11-03 live audit, Q4).
func TestLegacyObjectTypeFoldedIntoCurrent(t *testing.T) {
	ctx := context.Background()
	log, _ := newTestLog(t)
	a := Actor{UserID: "u", IP: "10.0.0.1"}
	for _, typ := range []string{"access_policy", "policy", "target"} {
		if _, err := log.Record(ctx, a.Event("policy.update", typ, "p1", Success, nil)); err != nil {
			t.Fatal(err)
		}
	}
	f, err := log.Facets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.ObjectTypes, ",") != "access_policy,target" {
		t.Fatalf("object types = %v, want access_policy and target once each", f.ObjectTypes)
	}
	got, _, err := log.List(ctx, Filter{ObjectType: "access_policy"})
	if err != nil || len(got) != 2 {
		t.Fatalf("filter access_policy = %d events (%v), want both spellings", len(got), err)
	}
	got, _, err = log.List(ctx, Filter{ObjectType: "target"})
	if err != nil || len(got) != 1 {
		t.Fatalf("filter target = %d events (%v), want 1", len(got), err)
	}
}
