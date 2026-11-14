// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// A Kubernetes cluster (ADR 0045) is a target whose API server makes it one:
// its address is the server's host, it serves kube and pod and nothing
// else, and it is exclusive with an engine and an upstream.
func TestKubernetesTargetValidate(t *testing.T) {
	c := &Target{Name: "prod", KubeAPIServer: " https://k8s.example.com:6443/ "}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid cluster: %v", err)
	}
	if c.KubeAPIServer != "https://k8s.example.com:6443" || c.Address != "k8s.example.com" {
		t.Fatalf("server %q address %q", c.KubeAPIServer, c.Address)
	}
	if !c.IsKubernetes() || c.Kind() != protocol.KindKubernetes || c.OSFamily != OtherOS {
		t.Fatalf("kind %q os %q", c.Kind(), c.OSFamily)
	}
	if !c.Impersonates() {
		t.Fatal("impersonation is the default")
	}
	if len(c.Capabilities) != 2 || c.Capabilities[0] != Kube || c.Capabilities[1] != Pod || len(c.Ports) != 0 {
		t.Fatalf("capabilities %v ports %v", c.Capabilities, c.Ports)
	}
	off := false
	shared := &Target{Name: "shared", KubeAPIServer: "https://10.0.0.5", KubeImpersonate: &off}
	if err := shared.Validate(); err != nil || shared.Impersonates() {
		t.Fatalf("impersonation off: %v, impersonates %v", err, shared.Impersonates())
	}

	for _, tc := range []struct {
		name string
		t    Target
		want string
	}{
		{"http", Target{Name: "x", KubeAPIServer: "http://k8s"}, "must be https"},
		{"no host", Target{Name: "x", KubeAPIServer: "https://"}, "must be https"},
		{"credentials in the url", Target{Name: "x", KubeAPIServer: "https://u:p@k8s"}, "must be https"},
		{"a path", Target{Name: "x", KubeAPIServer: "https://k8s/api"}, "carries a path"},
		{"a query", Target{Name: "x", KubeAPIServer: "https://k8s?x=1"}, "must be https"},
		{"with an engine", Target{Name: "x", KubeAPIServer: "https://k8s", Engine: "postgres"}, "not two of these"},
		{"with an upstream", Target{Name: "x", KubeAPIServer: "https://k8s", AppUpstream: "http://app"}, "not two of these"},
		{"a host port", Target{Name: "x", KubeAPIServer: "https://k8s", Ports: map[Protocol]int{SSH: 22}}, "has no ssh port"},
		{"ca that is not pem", Target{Name: "x", KubeAPIServer: "https://k8s", KubeCA: "nope"}, "kube_ca"},
		{"ca without a cluster", Target{Name: "x", Address: "10.0.0.1", OSFamily: Linux, KubeCA: "x"}, "needs kube_api_server"},
		{"impersonate without a cluster", Target{Name: "x", Address: "10.0.0.1", OSFamily: Linux, KubeImpersonate: &off}, "needs kube_api_server"},
	} {
		err := tc.t.Validate()
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

// The cluster's fields survive the store on both engines, the kind filter
// finds it and keeps it out of the hosts, and a credential binds to kube.
func TestKubernetesTargetOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		off := false
		c := &Target{Name: "prod", KubeAPIServer: "https://k8s.example.com:6443", KubeCA: testCAPEM, KubeImpersonate: &off, Tags: map[string]string{"env": "prod"}}
		if err := r.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
		host := &Target{Name: "web", Address: "10.0.0.9", OSFamily: Linux}
		if err := r.Create(ctx, host); err != nil {
			t.Fatal(err)
		}
		got, err := r.Get(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.KubeAPIServer != c.KubeAPIServer || got.KubeCA != strings.TrimSpace(testCAPEM) || got.KubeImpersonate == nil || *got.KubeImpersonate || got.Kind() != protocol.KindKubernetes {
			t.Fatalf("round trip: server %q ca %d impersonate %v kind %q", got.KubeAPIServer, len(got.KubeCA), got.KubeImpersonate, got.Kind())
		}
		if host2, _ := r.Get(ctx, host.ID); host2.KubeImpersonate != nil || host2.Kind() != protocol.KindHost {
			t.Fatalf("a host carries no impersonation switch: %v", host2.KubeImpersonate)
		}
		names := func(kind string) []string {
			out, _, err := r.List(ctx, "", 50, ListFilter{Kind: kind})
			if err != nil {
				t.Fatal(err)
			}
			var n []string
			for _, x := range out {
				n = append(n, x.Name)
			}
			return n
		}
		if n := names(KindKubernetes); len(n) != 1 || n[0] != "prod" {
			t.Fatalf("kind=kubernetes lists %v", n)
		}
		if n := names(KindHost); len(n) != 1 || n[0] != "web" {
			t.Fatalf("kind=host lists %v, a cluster is not a host", n)
		}
		// The platform filter and the inventory's per-platform counts, which
		// Fabric's tiles read; a cluster from before the column is vanilla.
		eks := &Target{Name: "eks-1", KubeAPIServer: "https://eks.example", KubePlatform: "EKS"}
		if err := r.Create(ctx, eks); err != nil || eks.KubePlatform != PlatformEKS {
			t.Fatalf("eks: %v %q", err, eks.KubePlatform)
		}
		byPlatform := func(p string) []string {
			out, _, err := r.List(ctx, "", 50, ListFilter{Kind: KindKubernetes, Platform: p})
			if err != nil {
				t.Fatal(err)
			}
			var n []string
			for _, x := range out {
				n = append(n, x.Name)
			}
			return n
		}
		if n := byPlatform(PlatformEKS); len(n) != 1 || n[0] != "eks-1" {
			t.Fatalf("platform=eks lists %v", n)
		}
		if n := byPlatform(PlatformVanilla); len(n) != 1 || n[0] != "prod" {
			t.Fatalf("platform=vanilla lists %v", n)
		}
		if _, err := db.ExecContext(ctx, db.Rebind("UPDATE targets SET kube_platform = NULL WHERE id = ?"), c.ID); err != nil {
			t.Fatal(err)
		}
		if n := byPlatform(PlatformVanilla); len(n) != 1 || n[0] != "prod" {
			t.Fatalf("a cluster from before the column must read as vanilla: %v", n)
		}
		inv, err := r.CountInventory(ctx)
		if err != nil || inv.Clusters != 2 || inv.ByPlatform[PlatformVanilla] != 1 || inv.ByPlatform[PlatformEKS] != 1 {
			t.Fatalf("inventory: %v %+v", err, inv)
		}
		if got, _ := r.Get(ctx, c.ID); got.KubePlatform != PlatformVanilla {
			t.Fatalf("a NULL platform reads as %q", got.KubePlatform)
		}

		// Impersonation turned back on is stored as on, not as unset.
		on := true
		got.KubeImpersonate = &on
		if err := r.Update(ctx, got); err != nil {
			t.Fatal(err)
		}
		if again, _ := r.Get(ctx, c.ID); again.KubeImpersonate == nil || !*again.KubeImpersonate {
			t.Fatalf("impersonation on after update: %v", again.KubeImpersonate)
		}
	})
}
