// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/cloud"
)

// An EKS role (ADR 0045, 8) is a credential with no secret: the region, the
// role and the cluster, and an ExternalId minted here. The vault refuses
// what is not a role, keeps the ExternalId through an edit, and has nothing
// to open or rotate.
func TestEKSCredential(t *testing.T) {
	v, _ := testVault(t)
	ctx := context.Background()
	role := &Credential{Name: "prod-role", Type: TypeKubeEKS, Mode: ModeVaulted, Username: "ignored",
		AWSRegion: " eu-west-2 ", AWSRoleARN: "arn:aws:iam::123456789012:role/zanskar-eks", EKSCluster: "prod"}
	if err := v.Create(ctx, role, nil, ""); err != nil {
		t.Fatal(err)
	}
	if role.HasSecret || role.Username != "" || role.AWSRegion != "eu-west-2" || !cloud.ExternalIDRe.MatchString(role.AWSExternalID) {
		t.Fatalf("created: %+v", role)
	}
	got, err := v.Get(ctx, role.ID)
	if err != nil || got.AWSRoleARN != role.AWSRoleARN || got.EKSCluster != "prod" || got.AWSExternalID != role.AWSExternalID {
		t.Fatalf("read back: %v %+v", err, got)
	}
	if _, err := v.Open(ctx, role.ID); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("open: %v", err)
	}
	if _, err := v.Rotate(ctx, role.ID, &Secret{Password: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rotate: %v", err)
	}
	// An edit moves the role to another region; the ExternalId stays, since
	// the trust policy that carries it was pasted by hand.
	upd, err := v.Update(ctx, role.ID, Metadata{Name: "prod-role", AWSRegion: "eu-west-1", AWSRoleARN: role.AWSRoleARN, EKSCluster: "prod-2"})
	if err != nil || upd.AWSRegion != "eu-west-1" || upd.EKSCluster != "prod-2" || upd.AWSExternalID != role.AWSExternalID {
		t.Fatalf("update: %v %+v", err, upd)
	}
	for name, c := range map[string]*Credential{
		"no region":      {Type: TypeKubeEKS, Mode: ModeVaulted, AWSRoleARN: role.AWSRoleARN, EKSCluster: "prod"},
		"a bad region":   {Type: TypeKubeEKS, Mode: ModeVaulted, AWSRegion: "Europe", AWSRoleARN: role.AWSRoleARN, EKSCluster: "prod"},
		"a user, no arn": {Type: TypeKubeEKS, Mode: ModeVaulted, AWSRegion: "eu-west-2", AWSRoleARN: "arn:aws:iam::123456789012:user/bob", EKSCluster: "prod"},
		"a bad cluster":  {Type: TypeKubeEKS, Mode: ModeVaulted, AWSRegion: "eu-west-2", AWSRoleARN: role.AWSRoleARN, EKSCluster: "prod cluster"},
		"an external id": {Type: TypeKubeEKS, Mode: ModeVaulted, AWSRegion: "eu-west-2", AWSRoleARN: role.AWSRoleARN, EKSCluster: "prod", AWSExternalID: "mine"},
		"user supplied":  {Type: TypeKubeEKS, Mode: ModeUserSupplied, AWSRegion: "eu-west-2", AWSRoleARN: role.AWSRoleARN, EKSCluster: "prod"},
		"a token's role": {Type: TypeKubeToken, Mode: ModeVaulted, AWSRegion: "eu-west-2"},
	} {
		c.Name = name
		if err := v.Create(ctx, c, &Secret{Password: "t"}, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if err := v.Create(ctx, &Credential{Name: "with a secret", Type: TypeKubeEKS, Mode: ModeVaulted, AWSRegion: "eu-west-2", AWSRoleARN: role.AWSRoleARN, EKSCluster: "prod"}, &Secret{Password: "t"}, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a secret on a role: %v", err)
	}
}

type fakeEKS struct{ check *cloud.EKSCheck }

func (f fakeEKS) Check(context.Context) *cloud.EKSCheck { return f.check }

// The setup route prints what the administrator pastes, with the trust
// policy only once the gateway's principal is known; the describe route is
// the test, answered 200 whatever the outcome, with the stage that failed.
func TestEKSSetupAndDescribe(t *testing.T) {
	var access cloud.EKSAccess
	check := &cloud.EKSCheck{OK: true, AssumedARN: "arn:aws:sts::123456789012:assumed-role/zanskar-eks/zanskar-gateway",
		Cluster: &cloud.EKSCluster{Name: "prod", Endpoint: "https://ABC.eks.amazonaws.com", CAPEM: "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n", AuthenticationMode: "API"}}
	e, _ := newHandlerEnvWith(t, func(h *AdminHandler) {
		h.EKS = func(_ context.Context, a cloud.EKSAccess) (EKSClient, error) {
			access = a
			return fakeEKS{check: check}, nil
		}
	})
	code, body := e.do("POST", "/api/v1/credentials", map[string]any{"name": "prod-role", "type": "kube_eks", "mode": "vaulted",
		"aws_region": "eu-west-2", "aws_role_arn": "arn:aws:iam::123456789012:role/zanskar-eks", "eks_cluster": "prod"})
	if code != 201 || !strings.Contains(body, `"aws_external_id":"zanskar-`) || strings.Contains(body, `"has_secret":true`) {
		t.Fatalf("create: %d %s", code, body)
	}
	id := idOf(t, body)
	// A token credential has no setup.
	code, tok := e.do("POST", "/api/v1/credentials", map[string]any{"name": "sa", "type": "kube_token", "mode": "vaulted", "password": "abc"})
	if code != 201 {
		t.Fatal(tok)
	}
	if code, body := e.do("GET", "/api/v1/credentials/"+idOf(t, tok)+"/eks/setup", nil); code != 409 || !strings.Contains(body, "not_eks") {
		t.Fatalf("setup on a token: %d %s", code, body)
	}

	code, body = e.do("GET", "/api/v1/credentials/"+id+"/eks/setup", nil)
	var setup EKSSetup
	if err := json.Unmarshal([]byte(body), &setup); err != nil || code != 200 {
		t.Fatalf("setup: %d %s", code, body)
	}
	// No identity resolver here: the principal is unknown and the trust
	// policy withheld, the rest printed.
	if setup.TrustPolicy != "" || setup.PrincipalSource != cloud.SourceNone || setup.ExternalID == "" || setup.Username != "zanskar" ||
		!strings.Contains(setup.PermissionsPolicy, "arn:aws:eks:eu-west-2:*:cluster/prod") ||
		!strings.Contains(setup.AccessEntry, "--principal-arn arn:aws:iam::123456789012:role/zanskar-eks --type STANDARD --username zanskar") ||
		!strings.Contains(setup.AwsAuth, "rolearn: arn:aws:iam::123456789012:role/zanskar-eks") || setup.RoleName != "zanskar-eks-prod" {
		t.Fatalf("setup: %+v", setup)
	}

	code, body = e.do("POST", "/api/v1/credentials/"+id+"/eks/describe", nil)
	var res cloud.EKSCheck
	if err := json.Unmarshal([]byte(body), &res); err != nil || code != 200 || !res.OK || res.Cluster == nil || res.Cluster.Endpoint != "https://ABC.eks.amazonaws.com" {
		t.Fatalf("describe: %d %s", code, body)
	}
	if access.Cluster != "prod" || access.Region != "eu-west-2" || access.RoleARN != "arn:aws:iam::123456789012:role/zanskar-eks" || access.ExternalID != setup.ExternalID {
		t.Fatalf("the client was built for %+v", access)
	}
	if n := auditCount(t, e.db, "credential.test"); n != 1 {
		t.Fatalf("credential.test events: %d", n)
	}
	// The role refused: 200, the stage named, audited as a failure.
	*check = cloud.EKSCheck{Stage: "assume", Error: "AccessDenied: not authorized to perform sts:AssumeRole"}
	code, body = e.do("POST", "/api/v1/credentials/"+id+"/eks/describe", nil)
	if code != 200 || !strings.Contains(body, `"stage":"assume"`) || strings.Contains(body, `"ok":true`) {
		t.Fatalf("refused: %d %s", code, body)
	}
}
