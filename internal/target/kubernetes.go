// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
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
	credID := t.Credentials[Kube]
	if credID == "" || h.Vault == nil {
		httpx.WriteError(w, r, http.StatusConflict, "no_credential", "no credential is bound to the cluster's kube slot")
		return
	}
	// The test goes to the address checked here, as a session does.
	dialIP, err := h.Prober.Resolve(r.Context(), t.Address)
	if err != nil {
		h.record(r, audit.TargetProbe, t.ID, audit.Failure, map[string]any{"address": t.Address, "error": err.Error()})
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, "address_forbidden", addressRefusal(err))
		return
	}
	opened, err := h.Vault.Open(r.Context(), credID)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	defer opened.Close()
	cred, err := KubeCredential(opened)
	if err != nil {
		httpx.WriteError(w, r, http.StatusConflict, "credential_unsuitable", err.Error())
		return
	}
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

// KubeCredential turns an opened credential into what the cluster client
// takes: a token, or a certificate with its key.
func KubeCredential(o *credential.Opened) (kubegw.Credential, error) {
	switch o.Type {
	case credential.TypeKubeToken:
		return kubegw.Credential{Token: o.Password}, nil
	case credential.TypeKubeClientCert:
		return kubegw.Credential{CertPEM: o.PrivateKey}, nil
	}
	return kubegw.Credential{}, errors.New("the kube slot needs a kube_token or kube_client_cert credential")
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
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(kubegw.Manifest(groups)))
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
