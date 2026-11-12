// SPDX-License-Identifier: Apache-2.0

package kubegw

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAPI is a Kubernetes API server for what the client asks: it checks the
// bearer token, answers /version, access reviews and the namespace list, and
// records the last request so a test can look at its headers.
type fakeAPI struct {
	token   string
	allow   map[string]bool // resource -> allowed, for impersonate reviews
	nsDeny  bool
	last    *http.Request
	proto   string
	version string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.last, f.proto = r, r.Proto
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == "/version":
		_ = json.NewEncoder(w).Encode(map[string]string{"gitVersion": f.version, "platform": "linux/amd64"})
	case r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" && r.Method == http.MethodPost:
		var in struct {
			Spec struct {
				ResourceAttributes struct {
					Verb, Resource string
				} `json:"resourceAttributes"`
			} `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]bool{"allowed": in.Spec.ResourceAttributes.Verb == "impersonate" && f.allow[in.Spec.ResourceAttributes.Resource]}})
	case r.URL.Path == "/api/v1/namespaces":
		if f.nsDeny {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{"metadata": map[string]string{"name": "default"}}, {"metadata": map[string]string{"name": "prod"}}}})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func start(t *testing.T, f *fakeAPI) (Endpoint, func()) {
	t.Helper()
	srv := httptest.NewUnstartedServer(f)
	srv.EnableHTTP2 = true // the client must still speak 1.1
	srv.StartTLS()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	return Endpoint{APIServer: srv.URL, CA: ca}, srv.Close
}

func TestClientTalksToTheClusterAsZanskar(t *testing.T) {
	f := &fakeAPI{token: "sa-token", allow: map[string]bool{"users": true, "groups": true}, version: "v1.31.2"}
	ep, stop := start(t, f)
	defer stop()
	ctx := context.Background()

	c, err := New(ep, Credential{Token: "sa-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	v, err := c.Version(ctx)
	if err != nil || v.GitVersion != "v1.31.2" {
		t.Fatalf("version: %v %+v", err, v)
	}
	if f.proto != "HTTP/1.1" {
		t.Fatalf("the client spoke %s; upgrades need HTTP/1.1", f.proto)
	}
	users, groups, err := c.MayImpersonate(ctx)
	if err != nil || !users || !groups {
		t.Fatalf("impersonate: %v users %v groups %v", err, users, groups)
	}
	ns, err := c.Namespaces(ctx)
	if err != nil || strings.Join(ns, ",") != "default,prod" {
		t.Fatalf("namespaces: %v %v", err, ns)
	}

	// Half the right: the review says so.
	f.allow = map[string]bool{"users": true}
	if users, groups, _ = c.MayImpersonate(ctx); !users || groups {
		t.Fatalf("users-only: users %v groups %v", users, groups)
	}
	// A credential that may not list namespaces is not an error: the
	// administrator reads the empty list beside the rest.
	f.nsDeny = true
	if ns, err = c.Namespaces(ctx); err != nil || len(ns) != 0 {
		t.Fatalf("namespaces forbidden: %v %v", err, ns)
	}
}

func TestClientRefusals(t *testing.T) {
	f := &fakeAPI{token: "right", version: "v1.31.0"}
	ep, stop := start(t, f)
	defer stop()
	ctx := context.Background()

	c, _ := New(ep, Credential{Token: "wrong"})
	if _, err := c.Version(ctx); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong token: %v", err)
	}
	// The enrolled CA is what the server is verified against: another CA
	// (here, the system roots) refuses the fake's self-signed certificate.
	c2, _ := New(Endpoint{APIServer: ep.APIServer}, Credential{Token: "right"})
	if _, err := c2.Version(ctx); err == nil || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("an unverified server must be refused, got %v", err)
	}
	var unknown x509.UnknownAuthorityError
	if _, err := c2.Version(ctx); !errors.As(err, &unknown) {
		t.Fatalf("want an unknown-authority error, got %v", err)
	}
	for name, ep := range map[string]Endpoint{
		"http":  {APIServer: "http://k8s"},
		"no ca": {APIServer: "https://k8s", CA: "not pem"},
	} {
		if _, err := New(ep, Credential{Token: "x"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestManifest(t *testing.T) {
	m := Manifest([]string{"ops", "data team", "sre"})
	for _, want := range []string{
		`"system:authenticated"`, `"zanskar:ops"`, `"zanskar:sre"`,
		"Not listed, their names cannot be RBAC resource names: data team",
		"verbs: [\"impersonate\"]", "kind: ClusterRoleBinding", "create token zanskar",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("manifest lacks %q", want)
		}
	}
	if strings.Contains(m, "zanskar:data team") {
		t.Error("a name with a space must not be an RBAC resource name")
	}
}
