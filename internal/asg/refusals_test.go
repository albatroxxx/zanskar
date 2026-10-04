// SPDX-License-Identifier: Apache-2.0

package asg

import (
	"net/http"
	"testing"
)

// TestGroupRoutesRefuseCleanly: every route that names a group answers an
// unknown one with 404, not an error page or a half-done change, and a
// credential binding without a credential is a 400 that changes nothing.
func TestGroupRoutesRefuseCleanly(t *testing.T) {
	e := newEnv(t)
	for _, rq := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/autoscaling-groups/nope", nil},
		{"PUT", "/api/v1/autoscaling-groups/nope", writeBody()},
		{"DELETE", "/api/v1/autoscaling-groups/nope", nil},
		{"GET", "/api/v1/autoscaling-groups/nope/instances", nil},
		{"POST", "/api/v1/autoscaling-groups/nope/sync", nil},
		{"GET", "/api/v1/autoscaling-groups/nope/iam", nil},
		{"POST", "/api/v1/autoscaling-groups/nope/test", nil},
		{"PUT", "/api/v1/autoscaling-groups/nope/credentials/ssh", map[string]string{"credential_id": "c1"}},
		{"DELETE", "/api/v1/autoscaling-groups/nope/credentials/ssh", nil},
	} {
		if code, out := e.do(rq.method, rq.path, rq.body, e.admin); code != http.StatusNotFound {
			t.Errorf("%s %s: %d %v, want 404", rq.method, rq.path, code, out)
		}
	}

	code, g := e.do("POST", "/api/v1/autoscaling-groups", writeBody(), e.admin)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, g)
	}
	id := g["id"].(string)
	creds := "/api/v1/autoscaling-groups/" + id + "/credentials/ssh"
	if code, out := e.do("PUT", creds, map[string]string{"credential_id": ""}, e.admin); code != http.StatusBadRequest {
		t.Fatalf("empty credential_id: %d %v, want 400", code, out)
	}
	if code, out := e.do("PUT", creds, map[string]any{"credential": "c1"}, e.admin); code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d %v, want 400", code, out)
	}
	if _, got := e.do("GET", "/api/v1/autoscaling-groups/"+id, nil, e.admin); got["credentials"] != nil && len(got["credentials"].(map[string]any)) != 0 {
		t.Fatalf("a refused binding changed the group: %v", got["credentials"])
	}
}
