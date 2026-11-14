// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"context"
	"net/http"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/cloud"
	"github.com/albatroxxx/zanskar/internal/httpx"
)

// An EKS role (ADR 0045, 8) is set up in three pastes, which the setup route
// prints: the role's trust policy, naming the gateway's principal and the
// ExternalId minted here; its permissions, to describe the cluster; and the
// mapping of the role to a Kubernetes user inside the cluster, an access
// entry or an aws-auth line, which the RBAC manifest the cluster's page
// prints then binds. The describe route is the test: the role assumed, the
// cluster described, its endpoint and CA answered for the Add form.

// EKSClient is what the describe route needs of a cloud.EKS.
type EKSClient interface {
	Check(ctx context.Context) *cloud.EKSCheck
}

// EKSSetup is what the administrator pastes, with where the gateway's
// principal came from (ADR 0023): a trust policy with a placeholder looks
// finished and is not, so it is "" until the principal is known.
type EKSSetup struct {
	GatewayPrincipal string `json:"gateway_principal,omitempty"`
	PrincipalSource  string `json:"principal_source"`
	PrincipalError   string `json:"principal_error,omitempty"`
	ExternalID       string `json:"external_id"`
	// RoleName is a suggestion for the role to create.
	RoleName          string `json:"role_name"`
	TrustPolicy       string `json:"trust_policy,omitempty"`
	PermissionsPolicy string `json:"permissions_policy"`
	// AccessEntry maps the role for a cluster whose authentication mode
	// includes API; AwsAuth for one on the ConfigMap. Username is what both
	// map it to, and what the RBAC binds.
	AccessEntry string `json:"access_entry"`
	AwsAuth     string `json:"aws_auth"`
	Username    string `json:"username"`
}

// EKSDescribeTimeout bounds the test: an AssumeRole and a DescribeCluster.
const EKSDescribeTimeout = 20 * time.Second

func (h *AdminHandler) eksCredential(w http.ResponseWriter, r *http.Request) *Credential {
	c, err := h.Vault.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return nil
	}
	if c.Type != TypeKubeEKS {
		httpx.WriteError(w, r, http.StatusConflict, "not_eks", "credential is not an EKS role")
		return nil
	}
	return c
}

func (h *AdminHandler) eksSetup(w http.ResponseWriter, r *http.Request) {
	c := h.eksCredential(w, r)
	if c == nil {
		return
	}
	id := cloud.Identity{Source: cloud.SourceNone}
	if h.Identity != nil {
		id = h.Identity.Get(r.Context())
	}
	out := EKSSetup{GatewayPrincipal: id.Principal, PrincipalSource: id.Source, PrincipalError: id.Error, ExternalID: c.AWSExternalID,
		RoleName: "zanskar-eks-" + c.EKSCluster, TrustPolicy: cloud.EKSTrustPolicy(id.Principal, c.AWSExternalID),
		PermissionsPolicy: cloud.EKSPermissionsPolicy(c.AWSRegion, c.EKSCluster),
		AccessEntry:       cloud.EKSAccessEntry(c.AWSRegion, c.EKSCluster, c.AWSRoleARN), AwsAuth: cloud.EKSAwsAuth(c.AWSRoleARN), Username: cloud.EKSUsername}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// eksDescribe answers POST /credentials/{id}/eks/describe: the role assumed
// and the cluster described, or which of the two failed and why. The
// answer is 200 either way, as an autoscaling group's access test is; the
// outcome is audited as the test of a target is.
func (h *AdminHandler) eksDescribe(w http.ResponseWriter, r *http.Request) {
	c := h.eksCredential(w, r)
	if c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), EKSDescribeTimeout)
	defer cancel()
	newEKS := h.EKS
	if newEKS == nil {
		newEKS = func(ctx context.Context, a cloud.EKSAccess) (EKSClient, error) { return cloud.NewEKS(ctx, a) }
	}
	client, err := newEKS(ctx, cloud.EKSAccess{AWSAccess: cloud.AWSAccess{Region: c.AWSRegion, RoleARN: c.AWSRoleARN, ExternalID: c.AWSExternalID}, Cluster: c.EKSCluster})
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	res := client.Check(ctx)
	outcome := audit.Success
	if !res.OK {
		outcome = audit.Failure
	}
	details := map[string]any{"name": c.Name, "cluster": c.EKSCluster, "region": c.AWSRegion, "stage": res.Stage}
	if res.Cluster != nil {
		details["endpoint"], details["authentication_mode"] = res.Cluster.Endpoint, res.Cluster.AuthenticationMode
	}
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(audit.CredentialTest, "credential", c.ID, outcome, details))
	httpx.WriteJSON(w, http.StatusOK, res)
}
