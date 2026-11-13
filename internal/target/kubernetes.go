// SPDX-License-Identifier: Apache-2.0

package target

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/cloud"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/gateway/kubegw"
	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/protocol"
)

// KubeTestTimeout bounds a cluster test, three calls to the API server.
const KubeTestTimeout = 20 * time.Second

// GroupNamer resolves a group's name, for the printed manifest; the group
// repository is one.
type GroupNamer interface {
	Get(ctx context.Context, id string) (*group.Group, error)
}

// KubeTest is what a cluster test found (ADR 0045, 1): the API server's
// version, whether Zanskar's credential may impersonate users and groups,
// and the namespaces it could list.
type KubeTest struct {
	Version          string   `json:"version"`
	ImpersonateUsers bool     `json:"impersonate_users"`
	ImpersonateGroup bool     `json:"impersonate_groups"`
	Namespaces       []string `json:"namespaces"`
	// NamespacesListed is false when the credential may not list them,
	// which impersonation alone does not grant.
	NamespacesListed bool `json:"namespaces_listed"`
}

// kubeTest answers POST /targets/{id}/kube/test: the cluster's probe. The
// credential bound to the kube slot is opened and used as Zanskar; nothing
// is recorded on the target, as a database's probe records nothing.
func (h *AdminHandler) kubeTest(w http.ResponseWriter, r *http.Request) {
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !t.IsKubernetes() {
		httpx.WriteError(w, r, http.StatusConflict, "not_a_cluster", "target is not a Kubernetes cluster")
		return
	}
	// The test goes to the address checked here, as a session does.
	dialIP, err := h.Prober.Resolve(r.Context(), t.Address)
	if err != nil {
		h.record(r, audit.TargetProbe, t.ID, audit.Failure, map[string]any{"address": t.Address, "error": err.Error()})
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, "address_forbidden", addressRefusal(err))
		return
	}
	cred, closeCred, err := ResolveKubeCredential(r.Context(), h.Vault, t)
	switch {
	case errors.Is(err, ErrKubeCredential):
		code := "credential_unsuitable"
		if t.Credentials[Kube] == "" {
			code = "no_credential"
		}
		httpx.WriteError(w, r, http.StatusConflict, code, strings.TrimPrefix(err.Error(), ErrKubeCredential.Error()+": "))
		return
	case err != nil:
		httpx.Internal(w, r, h.Log, err)
		return
	}
	defer closeCred()
	ctx, cancel := context.WithTimeout(r.Context(), KubeTestTimeout)
	defer cancel()
	c, err := kubegw.New(kubegw.Endpoint{APIServer: t.KubeAPIServer, CA: t.KubeCA, DialIP: dialIP}, cred)
	if err != nil {
		httpx.WriteError(w, r, http.StatusConflict, "cluster_unusable", err.Error())
		return
	}
	defer c.Close()
	res, err := runKubeTest(ctx, c)
	if err != nil {
		h.record(r, audit.TargetProbe, t.ID, audit.Failure, map[string]any{"address": t.Address, "error": err.Error()})
		code, name := http.StatusBadGateway, "cluster_unreachable"
		if errors.Is(err, kubegw.ErrUnauthorized) {
			code, name = http.StatusConflict, "credential_refused"
		}
		httpx.WriteError(w, r, code, name, err.Error())
		return
	}
	h.record(r, audit.TargetProbe, t.ID, audit.Success, map[string]any{"address": t.Address, "version": res.Version,
		"impersonate_users": res.ImpersonateUsers, "impersonate_groups": res.ImpersonateGroup, "namespaces": len(res.Namespaces)})
	httpx.WriteJSON(w, http.StatusOK, res)
}

func runKubeTest(ctx context.Context, c *kubegw.Client) (*KubeTest, error) {
	v, err := c.Version(ctx)
	if err != nil {
		return nil, err
	}
	users, groups, err := c.MayImpersonate(ctx)
	if err != nil {
		return nil, err
	}
	ns, err := c.Namespaces(ctx)
	if err != nil {
		return nil, err
	}
	if ns == nil {
		return &KubeTest{Version: v.GitVersion, ImpersonateUsers: users, ImpersonateGroup: groups, Namespaces: []string{}}, nil
	}
	return &KubeTest{Version: v.GitVersion, ImpersonateUsers: users, ImpersonateGroup: groups, Namespaces: ns, NamespacesListed: true}, nil
}

// ErrKubeCredential is what keeps the kube slot's credential from being
// used, said to the person at connect and to the administrator at test;
// never an internal error.
var ErrKubeCredential = errors.New("target: the cluster's credential cannot be used")

// KubeSlotAccepts says whether a credential of type ct may hold the kube
// slot of a cluster on platform p (ADR 0045, 8): an EKS cluster takes the
// role that reaches it and nothing else; every other platform takes a token
// or a client certificate, the standard path, which GKE and AKS take too
// until adapters of their own exist.
func KubeSlotAccepts(platform string, ct credential.Type) error {
	switch {
	case !ct.IsKube():
		return fmt.Errorf("%w: the kube slot takes a kube_token, kube_client_cert or kube_eks credential, not %s", ErrInvalid, ct)
	case platform == PlatformEKS && ct != credential.TypeKubeEKS:
		return fmt.Errorf("%w: an EKS cluster takes a kube_eks credential, the role that reaches it", ErrInvalid)
	case platform != PlatformEKS && ct == credential.TypeKubeEKS:
		return fmt.Errorf("%w: a kube_eks credential is for a cluster whose platform is eks", ErrInvalid)
	}
	return nil
}

// KubeTokener mints the bearer an EKS cluster accepts; cloud.EKS is one.
type KubeTokener interface {
	Token(context.Context) (string, error)
}

// NewEKS is cloud.NewEKS; tests swap it for a minter that never reaches AWS.
var NewEKS = func(ctx context.Context, a cloud.EKSAccess) (KubeTokener, error) { return cloud.NewEKS(ctx, a) }

// ResolveKubeCredential turns the credential on the cluster's kube slot into
// what the client takes: a token or a certificate opened from the vault, or
// for an EKS role a source of bearers minted as the role. close releases
// what was opened and may be called as soon as the client is built, since
// the client keeps its own copy. A refusal wraps ErrKubeCredential.
func ResolveKubeCredential(ctx context.Context, vault *credential.Vault, t *Target) (kubegw.Credential, func(), error) {
	none := func() {}
	credID := t.Credentials[Kube]
	if credID == "" || vault == nil {
		return kubegw.Credential{}, none, fmt.Errorf("%w: no credential is bound to the cluster's kube slot", ErrKubeCredential)
	}
	c, err := vault.Get(ctx, credID)
	if err != nil {
		return kubegw.Credential{}, none, err
	}
	if c.Mode != credential.ModeVaulted {
		return kubegw.Credential{}, none, fmt.Errorf("%w: a cluster's credential is held by Zanskar", ErrKubeCredential)
	}
	if err := KubeSlotAccepts(t.KubePlatform, c.Type); err != nil {
		return kubegw.Credential{}, none, fmt.Errorf("%w: %s", ErrKubeCredential, strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
	}
	if c.Type == credential.TypeKubeEKS {
		e, err := NewEKS(ctx, cloud.EKSAccess{AWSAccess: cloud.AWSAccess{Region: c.AWSRegion, RoleARN: c.AWSRoleARN, ExternalID: c.AWSExternalID}, Cluster: c.EKSCluster})
		if err != nil {
			return kubegw.Credential{}, none, err
		}
		return kubegw.Credential{Bearer: e.Token}, none, nil
	}
	opened, err := vault.Open(ctx, credID)
	if err != nil {
		return kubegw.Credential{}, none, err
	}
	if c.Type == credential.TypeKubeToken {
		return kubegw.Credential{Token: opened.Password}, opened.Close, nil
	}
	// Close zeroes what Open decrypted; the client keeps its own copy.
	return kubegw.Credential{CertPEM: bytes.Clone(opened.PrivateKey)}, opened.Close, nil
}

// kubeManifest answers GET /targets/{id}/kube/manifest: the RBAC the cluster
// needs, naming the Zanskar groups whose policies grant this cluster so the
// administrator binds roles to them.
func (h *AdminHandler) kubeManifest(w http.ResponseWriter, r *http.Request) {
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !t.IsKubernetes() {
		httpx.WriteError(w, r, http.StatusConflict, "not_a_cluster", "target is not a Kubernetes cluster")
		return
	}
	groups, err := h.kubeGroups(r.Context(), t)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	text := kubegw.Manifest(groups)
	if t.KubePlatform == PlatformEKS {
		// The role's mapping, printed with the role when the slot holds it
		// (ADR 0045, 8); the administrator fills the blanks otherwise.
		mapping := "aws eks create-access-entry --cluster-name <cluster> --principal-arn <role arn> --type STANDARD --username " + cloud.EKSUsername
		if id := t.Credentials[Kube]; id != "" && h.Vault != nil {
			if c, err := h.Vault.Get(r.Context(), id); err == nil && c.Type == credential.TypeKubeEKS {
				mapping = cloud.EKSAccessEntry(c.AWSRegion, c.EKSCluster, c.AWSRoleARN) + "\nor, on the aws-auth ConfigMap, under mapRoles:\n" + cloud.EKSAwsAuth(c.AWSRoleARN)
			}
		}
		text = kubegw.ManifestEKS(groups, cloud.EKSUsername, mapping)
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(text))
}

// kubeSlotAllowed refuses, before anything is saved, a kube slot holding a
// credential the cluster's platform does not take (KubeSlotAccepts).
func (h *AdminHandler) kubeSlotAllowed(w http.ResponseWriter, r *http.Request, t *Target) bool {
	id := t.Credentials[Kube]
	if id == "" || h.Vault == nil {
		return true
	}
	c, err := h.Vault.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, credential.ErrNotFound) {
			httpx.BadRequest(w, r, "credential does not exist")
			return false
		}
		httpx.Internal(w, r, h.Log, err)
		return false
	}
	if err := KubeSlotAccepts(t.KubePlatform, c.Type); err != nil {
		httpx.BadRequest(w, r, strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
		return false
	}
	return true
}

// kubeGroups names the groups whose policies hold a kubernetes grant that
// names the cluster or matches its tags, sorted, each once.
func (h *AdminHandler) kubeGroups(ctx context.Context, t *Target) ([]string, error) {
	if h.Policies == nil || h.Groups == nil {
		return nil, nil
	}
	seen := map[string]bool{}
	after := ""
	for {
		batch, next, err := h.Policies.List(ctx, after, 500)
		if err != nil {
			return nil, err
		}
		for _, p := range batch {
			if !grantsCluster(p, t) {
				continue
			}
			for _, s := range p.Subjects {
				if s.Kind == "group" {
					seen[s.ID] = true
				}
			}
		}
		if next == "" {
			break
		}
		after = next
	}
	var names []string
	for id := range seen {
		g, err := h.Groups.Get(ctx, id)
		if err != nil {
			continue // a group deleted since; its policy no longer admits anyone through it
		}
		names = append(names, g.Name)
	}
	sort.Strings(names)
	return names, nil
}

func grantsCluster(p *policy.Policy, t *Target) bool {
	for _, g := range p.Grants {
		if g.Kind != protocol.KindKubernetes {
			continue
		}
		for _, gt := range g.Targets {
			if gt.ID == t.ID {
				return true
			}
		}
		if g.Tags != nil && g.Tags.Matches(t.Tags) {
			return true
		}
	}
	return false
}
