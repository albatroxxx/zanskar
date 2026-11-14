// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/cloud"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/protocol"
)

// A fake API server for the cluster test: it checks the bearer token and
// answers the three calls the test makes.
func fakeCluster(t *testing.T, token string) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"gitVersion": "v1.31.1"})
		case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]bool{"allowed": true}})
		case "/api/v1/namespaces":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{"metadata": map[string]string{"name": "prod"}}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
}

// TestKubernetesTestAndManifest: a cluster enrolled through the API, its
// credential on the kube slot, tested against a fake API server as Zanskar;
// and the RBAC manifest naming the groups whose policies grant it.
func TestKubernetesTestAndManifest(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	srv, ca := fakeCluster(t, "sa-token")

	code, body := e.do("POST", "/api/v1/targets", map[string]any{"name": "prod-k8s", "kube_api_server": srv.URL, "kube_ca": ca, "tags": map[string]string{"env": "prod"}}, e.admin)
	if code != 201 || body["kube_api_server"] != srv.URL || body["address"] != "127.0.0.1" || body["kube_impersonate"] != true {
		t.Fatalf("create: %d %v", code, body)
	}
	id := body["id"].(string)
	if caps, _ := body["capabilities"].([]any); len(caps) != 2 || caps[0] != "kube" || caps[1] != "pod" {
		t.Fatalf("capabilities: %v", body["capabilities"])
	}

	// Nothing on the slot yet.
	if code, body := e.do("POST", "/api/v1/targets/"+id+"/kube/test", nil, e.admin); code != 409 || body["code"] != "no_credential" {
		t.Fatalf("test with no credential: %d %v", code, body)
	}
	// A host is not a cluster.
	code, host := e.do("POST", "/api/v1/targets", map[string]any{"name": "box", "address": "10.0.0.1", "os_family": "linux"}, e.admin)
	if code != 201 {
		t.Fatal(host)
	}
	if code, body := e.do("POST", "/api/v1/targets/"+host["id"].(string)+"/kube/test", nil, e.admin); code != 409 || body["code"] != "not_a_cluster" {
		t.Fatalf("test on a host: %d %v", code, body)
	}

	tok := &credential.Credential{Name: "sa", Type: credential.TypeKubeToken, Mode: credential.ModeVaulted}
	if err := e.vault.Create(ctx, tok, &credential.Secret{Password: "sa-token"}, ""); err != nil {
		t.Fatal(err)
	}
	if code, body := e.do("PUT", "/api/v1/targets/"+id+"/credentials/kube", map[string]string{"credential_id": tok.ID}, e.admin); code != 200 {
		t.Fatalf("bind: %d %v", code, body)
	}
	code, body = e.do("POST", "/api/v1/targets/"+id+"/kube/test", nil, e.admin)
	if code != 200 || body["version"] != "v1.31.1" || body["impersonate_users"] != true || body["impersonate_groups"] != true || body["namespaces_listed"] != true {
		t.Fatalf("test: %d %v", code, body)
	}
	if ns, _ := body["namespaces"].([]any); len(ns) != 1 || ns[0] != "prod" {
		t.Fatalf("namespaces: %v", body["namespaces"])
	}
	events, _, err := e.audit.List(ctx, audit.Filter{Action: "target.probe", Limit: 1})
	if err != nil || len(events) != 1 || events[0].Outcome != audit.Success || !strings.Contains(string(events[0].Details), `"version":"v1.31.1"`) {
		t.Fatalf("probe audit: %v %+v", err, events)
	}

	// A wrong token is the cluster refusing the credential, said as such.
	wrong := &credential.Credential{Name: "wrong", Type: credential.TypeKubeToken, Mode: credential.ModeVaulted}
	_ = e.vault.Create(ctx, wrong, &credential.Secret{Password: "other"}, "")
	e.do("PUT", "/api/v1/targets/"+id+"/credentials/kube", map[string]string{"credential_id": wrong.ID}, e.admin)
	if code, body := e.do("POST", "/api/v1/targets/"+id+"/kube/test", nil, e.admin); code != 409 || body["code"] != "credential_refused" {
		t.Fatalf("wrong token: %d %v", code, body)
	}
	// A password is not a cluster credential: the slot refuses it, and keeps
	// what it held.
	pw := &credential.Credential{Name: "pw", Type: credential.TypePassword, Mode: credential.ModeVaulted, Username: "u"}
	_ = e.vault.Create(ctx, pw, &credential.Secret{Password: "p"}, "")
	if code, body := e.do("PUT", "/api/v1/targets/"+id+"/credentials/kube", map[string]string{"credential_id": pw.ID}, e.admin); code != 400 || !strings.Contains(body["message"].(string), "kube slot takes") {
		t.Fatalf("password on the slot: %d %v", code, body)
	}
	if code, body := e.do("GET", "/api/v1/targets/"+id, nil, e.admin); code != 200 || body["credentials"].(map[string]any)["kube"] != wrong.ID {
		t.Fatalf("the slot changed: %d %v", code, body["credentials"])
	}

	// The manifest names the groups whose policies grant the cluster, by
	// name or by tag, and leaves out a group whose policy grants something
	// else.
	groups := group.NewRepo(e.db)
	ops := &group.Group{Name: "ops"}
	data := &group.Group{Name: "data"}
	other := &group.Group{Name: "other"}
	for _, g := range []*group.Group{ops, data, other} {
		if err := groups.Create(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []*policy.Policy{
		{Name: "by-name", Subjects: []policy.Subject{{Kind: "group", ID: ops.ID}}, Grants: []policy.Grant{{Kind: protocol.KindKubernetes, Targets: []policy.GrantTarget{{ID: id, Protocols: []string{"kube"}}}}}},
		{Name: "by-tag", Subjects: []policy.Subject{{Kind: "group", ID: data.ID}}, Grants: []policy.Grant{{Kind: protocol.KindKubernetes, Tags: &policy.TagMatch{Match: map[string][]string{"env": {"prod"}}, Protocols: []string{"kube"}}}}},
		{Name: "hosts", Subjects: []policy.Subject{{Kind: "group", ID: other.ID}}, Grants: []policy.Grant{{Kind: protocol.KindHost, Targets: []policy.GrantTarget{{ID: host["id"].(string), Protocols: []string{"ssh"}}}}}},
	} {
		if err := e.policies.Create(ctx, p); err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/targets/"+id+"/kube/manifest", nil)
	req.AddCookie(e.admin)
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	m := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "yaml") {
		t.Fatalf("manifest: %d %s", rec.Code, m)
	}
	for _, want := range []string{`"zanskar:ops"`, `"zanskar:data"`, "kind: ClusterRoleBinding"} {
		if !strings.Contains(m, want) {
			t.Errorf("manifest lacks %s:\n%s", want, m)
		}
	}
	if strings.Contains(m, "zanskar:other") {
		t.Error("a group whose policy grants only hosts is listed")
	}
}

// A cluster's live sessions hold its endpoint, CA, platform, the way they
// act and the credential they started with (ADR 0045): a change to any of
// these ends them; a tag or a note does not.
func TestKubernetesEditEndsSessions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	srv, ca := fakeCluster(t, "sa-token")
	code, body := e.do("POST", "/api/v1/targets", map[string]any{"name": "prod-k8s", "kube_api_server": srv.URL, "kube_ca": ca}, e.admin)
	if code != 201 {
		t.Fatal(body)
	}
	id := body["id"].(string)
	put := func(patch map[string]any) {
		t.Helper()
		b := map[string]any{"name": "prod-k8s", "kube_api_server": srv.URL, "kube_ca": ca, "kube_platform": "vanilla", "kube_impersonate": true, "tags": map[string]string{}, "notes": ""}
		for k, v := range patch {
			b[k] = v
		}
		if code, out := e.do("PUT", "/api/v1/targets/"+id, b, e.admin); code != 200 {
			t.Fatalf("update %v: %d %v", patch, code, out)
		}
	}
	e.revoker.disabled = nil
	put(map[string]any{"tags": map[string]string{"env": "prod"}, "notes": "renamed nothing"})
	if len(e.revoker.disabled) != 0 {
		t.Fatalf("a tag ended the sessions: %v", e.revoker.disabled)
	}
	for name, patch := range map[string]map[string]any{
		"the CA":       {"kube_ca": ""},
		"the way":      {"kube_impersonate": false},
		"the platform": {"kube_platform": "gke"},
		"the endpoint": {"kube_api_server": "https://10.0.0.9:6443"},
	} {
		e.revoker.disabled = nil
		put(patch)
		if len(e.revoker.disabled) != 1 || e.revoker.disabled[0] != id {
			t.Errorf("%s changed: sessions ended for %v", name, e.revoker.disabled)
		}
		put(nil)
	}
	// The credential on the slot, bound or unbound.
	tok := &credential.Credential{Name: "sa", Type: credential.TypeKubeToken, Mode: credential.ModeVaulted}
	if err := e.vault.Create(ctx, tok, &credential.Secret{Password: "sa-token"}, ""); err != nil {
		t.Fatal(err)
	}
	e.revoker.disabled = nil
	if code, out := e.do("PUT", "/api/v1/targets/"+id+"/credentials/kube", map[string]string{"credential_id": tok.ID}, e.admin); code != 200 {
		t.Fatalf("bind: %d %v", code, out)
	}
	if code, _ := e.do("DELETE", "/api/v1/targets/"+id+"/credentials/kube", nil, e.admin); code != 204 {
		t.Fatalf("unbind: %d", code)
	}
	if len(e.revoker.disabled) != 2 {
		t.Fatalf("slot changes ended sessions %d times, want 2", len(e.revoker.disabled))
	}
}

// fakeMinter mints what the fake cluster accepts, or fails as AWS would.
type fakeMinter struct {
	token string
	err   error
}

func (m fakeMinter) Token(context.Context) (string, error) { return m.token, m.err }

// TestKubernetesEKS (ADR 0045, 8): an EKS cluster's kube slot takes the role
// that reaches it and nothing else, a vanilla cluster refuses that role, the
// test runs with a token minted as the role, and the manifest binds the user
// the cluster maps the role to, with the mapping step printed.
func TestKubernetesEKS(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	srv, ca := fakeCluster(t, "k8s-aws-v1.(fake)")
	prev := NewEKS
	NewEKS = func(_ context.Context, a cloud.EKSAccess) (KubeTokener, error) {
		if a.Cluster != "prod" || a.Region != "eu-west-2" || a.ExternalID == "" {
			return nil, errors.New("the credential's role was not what the minter was given")
		}
		return fakeMinter{token: "k8s-aws-v1.(fake)"}, nil
	}
	t.Cleanup(func() { NewEKS = prev })

	role := &credential.Credential{Name: "prod-role", Type: credential.TypeKubeEKS, Mode: credential.ModeVaulted,
		AWSRegion: "eu-west-2", AWSRoleARN: "arn:aws:iam::123456789012:role/zanskar-eks", EKSCluster: "prod"}
	if err := e.vault.Create(ctx, role, nil, ""); err != nil {
		t.Fatal(err)
	}
	tok := &credential.Credential{Name: "sa", Type: credential.TypeKubeToken, Mode: credential.ModeVaulted}
	if err := e.vault.Create(ctx, tok, &credential.Secret{Password: "sa-token"}, ""); err != nil {
		t.Fatal(err)
	}
	// The role in the body on create, as the Add form sends it.
	code, body := e.do("POST", "/api/v1/targets", map[string]any{"name": "prod-eks", "kube_api_server": srv.URL, "kube_ca": ca, "kube_platform": "eks",
		"credentials": map[string]string{"kube": role.ID}}, e.admin)
	if code != 201 || body["kube_platform"] != "eks" {
		t.Fatalf("create: %d %v", code, body)
	}
	id := body["id"].(string)
	// A token on an EKS cluster, or the role on a vanilla one: refused.
	if code, body := e.do("PUT", "/api/v1/targets/"+id+"/credentials/kube", map[string]string{"credential_id": tok.ID}, e.admin); code != 400 || !strings.Contains(body["message"].(string), "kube_eks") {
		t.Fatalf("token on eks: %d %v", code, body)
	}
	if code, body := e.do("POST", "/api/v1/targets", map[string]any{"name": "plain", "kube_api_server": srv.URL, "credentials": map[string]string{"kube": role.ID}}, e.admin); code != 400 || !strings.Contains(body["message"].(string), "platform is eks") {
		t.Fatalf("role on vanilla: %d %v", code, body)
	}
	// The test reaches the cluster with the minted token.
	code, body = e.do("POST", "/api/v1/targets/"+id+"/kube/test", nil, e.admin)
	if code != 200 || body["version"] != "v1.31.1" {
		t.Fatalf("test: %d %v", code, body)
	}
	// The manifest binds the user, not a service account, and prints the mapping.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/targets/"+id+"/kube/manifest", nil)
	req.AddCookie(e.admin)
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	m := rec.Body.String()
	for _, want := range []string{"kind: User\n    name: zanskar", "create-access-entry --region eu-west-2 --cluster-name prod --principal-arn arn:aws:iam::123456789012:role/zanskar-eks", "rolearn: arn:aws:iam::123456789012:role/zanskar-eks"} {
		if !strings.Contains(m, want) {
			t.Errorf("manifest lacks %q:\n%s", want, m)
		}
	}
	if strings.Contains(m, "ServiceAccount") || strings.Contains(m, "create token") {
		t.Errorf("an EKS manifest names a service account:\n%s", m)
	}
	// A minter AWS refuses: the test says the credential failed, not the cluster.
	NewEKS = func(context.Context, cloud.EKSAccess) (KubeTokener, error) {
		return fakeMinter{err: errors.New("AccessDenied")}, nil
	}
	if code, body := e.do("POST", "/api/v1/targets/"+id+"/kube/test", nil, e.admin); code != 502 || !strings.Contains(body["message"].(string), "AccessDenied") {
		t.Fatalf("minter refused: %d %v", code, body)
	}
}
