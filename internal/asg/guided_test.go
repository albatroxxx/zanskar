// SPDX-License-Identifier: Apache-2.0

package asg

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/cloud"
)

// TestGuidedEnrolment covers ADR 0023 at the HTTP layer: an IAM preview
// mints the ExternalId and renders the real principal, the access test
// distinguishes the trust policy, the permissions and a missing group, a
// group is created with the previewed ExternalId, and the saved group can
// be tested and shown its documents.
func TestGuidedEnrolment(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	code, body := e.do("POST", "/api/v1/autoscaling-groups/iam-preview", map[string]any{"region": "ap-south-1", "external_name": "web-asg"}, e.admin)
	if code != 200 {
		t.Fatalf("preview: %d %v", code, body)
	}
	ext, _ := body["external_id"].(string)
	if !strings.HasPrefix(ext, "zanskar-") || body["principal_source"] != "environment" || body["gateway_principal"] != "arn:aws:iam::111111111111:role/zanskar-gateway" {
		t.Fatalf("preview identity: %v", body)
	}
	trust, _ := body["trust_policy"].(string)
	cli, _ := body["cli"].(string)
	cf, _ := body["cloudformation"].(string)
	if !strings.Contains(trust, ext) || !strings.Contains(trust, "arn:aws:iam::111111111111:role/zanskar-gateway") || strings.Contains(trust, "<") {
		t.Fatalf("trust policy: %s", trust)
	}
	if body["role_name"] != "zanskar-web-asg" || !strings.Contains(cli, "aws iam create-role --role-name zanskar-web-asg") || !strings.Contains(cf, "RoleName: zanskar-web-asg") {
		t.Fatalf("role docs: %v", body)
	}
	// The same ExternalId can be previewed again (the customer re-opens the step).
	if code, body = e.do("POST", "/api/v1/autoscaling-groups/iam-preview", map[string]any{"region": "ap-south-1", "external_name": "web-asg", "external_id": ext}, e.admin); code != 200 || body["external_id"] != ext {
		t.Fatalf("preview with id: %d %v", code, body)
	}
	if code, body = e.do("POST", "/api/v1/autoscaling-groups/iam-preview", map[string]any{"region": "ap-south-1", "external_name": "web-asg", "external_id": "made-up"}, e.admin); code != 400 {
		t.Fatalf("foreign external id must be refused: %d %v", code, body)
	}

	// Access test before the group exists: trust failure, then permissions,
	// then no such group, then OK.
	req := map[string]any{"region": "ap-south-1", "external_name": "web-asg", "role_arn": "arn:aws:iam::123456789012:role/zanskar-web-asg", "external_id": ext}
	e.fake.Err = errors.New("AccessDenied: not authorized to perform sts:AssumeRole")
	if code, body = e.do("POST", "/api/v1/autoscaling-groups/test", req, e.admin); code != 200 || body["ok"] != false || body["stage"] != "assume" {
		t.Fatalf("assume failure: %d %v", code, body)
	}
	e.fake.Err = nil
	if code, body = e.do("POST", "/api/v1/autoscaling-groups/test", req, e.admin); code != 200 || body["ok"] != false || body["stage"] != "group" || body["assumed_arn"] == "" {
		t.Fatalf("missing group: %d %v", code, body)
	}
	e.fake.Set("web-asg", cloud.Instance{ID: "i-1", LifecycleState: "InService", PrivateIP: "10.0.0.1"})
	if code, body = e.do("POST", "/api/v1/autoscaling-groups/test", req, e.admin); code != 200 || body["ok"] != true || body["instance_count"] != float64(1) {
		t.Fatalf("ok: %d %v", code, body)
	}
	if code, body = e.do("POST", "/api/v1/autoscaling-groups/test", map[string]any{"region": "ap-south-1", "external_name": "web-asg", "role_arn": "arn:aws:iam::123456789012:role/x"}, e.admin); code != 400 {
		t.Fatalf("test without external id: %d %v", code, body)
	}

	// Create with the previewed ExternalId; the saved group carries it.
	create := map[string]any{"name": "web", "region": "ap-south-1", "external_name": "web-asg", "role_arn": "arn:aws:iam::123456789012:role/zanskar-web-asg",
		"external_id": ext, "os_family": "linux", "capabilities": []string{"ssh"}}
	code, body = e.do("POST", "/api/v1/autoscaling-groups", create, e.admin)
	if code != 201 || body["external_id"] != ext {
		t.Fatalf("create with external id: %d %v", code, body)
	}
	id := body["id"].(string)
	if code, body = e.do("POST", "/api/v1/autoscaling-groups/"+id+"/test", nil, e.admin); code != 200 || body["ok"] != true {
		t.Fatalf("test saved group: %d %v", code, body)
	}
	if code, body = e.do("GET", "/api/v1/autoscaling-groups/"+id+"/iam", nil, e.admin); code != 200 || body["external_id"] != ext || body["principal_source"] != "environment" || body["cli"] == nil {
		t.Fatalf("iam docs: %d %v", code, body)
	}
	if code, _ := e.do("POST", "/api/v1/autoscaling-groups/"+id+"/test", nil, e.user); code != 403 {
		t.Fatalf("non-admin: %d", code)
	}

	// Identity endpoints.
	if code, body = e.do("GET", "/api/v1/admin/aws/identity", nil, e.admin); code != 200 || body["source"] != "environment" {
		t.Fatalf("identity: %d %v", code, body)
	}
	if code, body = e.do("POST", "/api/v1/admin/aws/identity/refresh", nil, e.admin); code != 200 || body["principal"] != "arn:aws:iam::111111111111:role/zanskar-gateway" {
		t.Fatalf("identity refresh: %d %v", code, body)
	}

	events, _, err := e.audit.List(ctx, audit.Filter{Action: "asg.test"})
	if err != nil {
		t.Fatal(err)
	}
	var ok, failed int
	for _, ev := range events {
		if ev.Outcome == audit.Success {
			ok++
		} else {
			failed++
		}
	}
	if ok != 2 || failed != 2 {
		t.Fatalf("audited tests: %d ok, %d failed, want 2 and 2", ok, failed)
	}
}

// TestNoPrincipalNoPlaceholder: without an identity the documents withhold
// the trust policy and the scripts instead of inventing an ARN.
func TestNoPrincipalNoPlaceholder(t *testing.T) {
	e := newEnv(t)
	h := &AdminHandler{Repo: e.repo, Identity: nil}
	docs := h.iamDocs(context.Background(), &Group{ExternalID: "zanskar-0123456789abcdef0123456789abcdef", ExternalName: "web-asg", Region: "ap-south-1"})
	if docs.PrincipalSource != cloud.SourceNone || docs.TrustPolicy != "" || docs.CLI != "" || docs.CloudFormation != "" || docs.PermissionsPolicy == "" {
		t.Fatalf("docs without a principal: %+v", docs)
	}
}
