// SPDX-License-Identifier: Apache-2.0

package kubegw

import (
	"net/url"
	"strings"
	"testing"
)

// The guard-rail (ADR 0045, 4): a request names its namespace or it is
// cluster-wide; the scope admits it or says what it covers.
func TestGuard(t *testing.T) {
	prod := Scope{Namespaces: []string{"prod", "data"}}
	all := Scope{}
	cluster := Scope{ClusterScope: true}
	pf := Scope{Namespaces: []string{"prod"}, PortForward: true}
	cases := []struct {
		method, path, query string
		scope               Scope
		ok                  bool
		label, why          string
	}{
		// Discovery: every session, every scope.
		{"GET", "/api", "", prod, true, "get", ""},
		{"GET", "/api/v1", "", prod, true, "get", ""},
		{"GET", "/apis", "", prod, true, "get", ""},
		{"GET", "/apis/apps", "", prod, true, "get", ""},
		{"GET", "/apis/apps/v1", "", prod, true, "get", ""},
		{"GET", "/version", "", prod, true, "get", ""},
		{"GET", "/openapi/v3", "", prod, true, "get", ""},
		// Namespaced requests in a granted namespace.
		{"GET", "/api/v1/namespaces/prod/pods", "", prod, true, "list pods -n prod", ""},
		{"GET", "/api/v1/namespaces/prod/pods", "watch=true", prod, true, "watch pods -n prod", ""},
		{"GET", "/api/v1/namespaces/prod/pods/web-1", "", prod, true, "get pods/web-1 -n prod", ""},
		{"GET", "/api/v1/namespaces/prod/pods/web-1/log", "follow=true", prod, true, "log pods/web-1 -n prod", ""},
		{"POST", "/apis/apps/v1/namespaces/data/deployments", "", prod, true, "create deployments -n data", ""},
		{"PATCH", "/apis/apps/v1/namespaces/data/deployments/api", "", prod, true, "patch deployments/api -n data", ""},
		{"PUT", "/apis/apps/v1/namespaces/data/deployments/api", "", prod, true, "update deployments/api -n data", ""},
		{"DELETE", "/apis/apps/v1/namespaces/data/deployments/api", "", prod, true, "delete deployments/api -n data", ""},
		{"DELETE", "/apis/apps/v1/namespaces/data/deployments", "", prod, true, "deletecollection deployments -n data", ""},
		{"GET", "/api/v1/namespaces/prod/services/web/proxy/healthz", "", prod, true, "proxy services/web -n prod", ""},
		{"POST", "/api/v1/namespaces/prod/pods/web-1/exec", "command=sh", prod, true, "exec pods/web-1 -n prod", ""},
		// Reviews of the caller alone (auth whoami, auth can-i) pass under any
		// scope; a review of someone else is cluster-wide (kind v1.37, 2026-11-14).
		{"POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews", "", prod, true, "create selfsubjectreviews", ""},
		{"POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "", prod, true, "create selfsubjectaccessreviews", ""},
		{"POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "", prod, true, "create selfsubjectrulesreviews", ""},
		{"POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", "", prod, false, "create subjectaccessreviews", "name one (-n)"},
		// The namespace object itself reads as a request in it.
		{"GET", "/api/v1/namespaces/prod", "", prod, true, "get namespaces -n prod", ""},
		// Outside the granted namespaces.
		{"GET", "/api/v1/namespaces/kube-system/pods", "", prod, false, "list pods -n kube-system", "covers the namespaces prod, data only, not kube-system"},
		{"GET", "/api/v1/namespaces/kube-system", "", prod, false, "get namespaces -n kube-system", "not kube-system"},
		// Cluster-wide: nodes, the namespace list, and -A alike, without cluster scope.
		{"GET", "/api/v1/nodes", "", prod, false, "list nodes", "covers the namespaces prod, data only; name one (-n)"},
		{"GET", "/api/v1/namespaces", "", prod, false, "list namespaces", "name one (-n)"},
		{"GET", "/api/v1/pods", "", prod, false, "list pods", "name one (-n)"},
		{"GET", "/api/v1/pods", "", all, false, "list pods", "namespaced resources only; name a namespace (-n)"},
		{"GET", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "", all, false, "list customresourcedefinitions", "namespaced resources only"},
		// With cluster scope, everything.
		{"GET", "/api/v1/nodes", "", cluster, true, "list nodes", ""},
		{"GET", "/api/v1/pods", "", cluster, true, "list pods", ""},
		{"GET", "/api/v1/namespaces/kube-system/pods", "", cluster, true, "list pods -n kube-system", ""},
		{"DELETE", "/api/v1/nodes/n1", "", cluster, true, "delete nodes/n1", ""},
		// Port-forward is its own switch.
		{"POST", "/api/v1/namespaces/prod/pods/web-1/portforward", "", prod, false, "portforward pods/web-1 -n prod", "does not include port-forward"},
		{"POST", "/api/v1/namespaces/prod/pods/web-1/portforward", "", pf, true, "portforward pods/web-1 -n prod", ""},
		{"POST", "/api/v1/namespaces/prod/pods/web-1/portforward", "", cluster, false, "portforward pods/web-1 -n prod", "does not include port-forward"},
	}
	for _, c := range cases {
		q, _ := url.ParseQuery(c.query)
		r, ok := Parse(c.method, c.path, q)
		if !ok {
			t.Errorf("%s %s: not an API path", c.method, c.path)
			continue
		}
		if got := r.Label(); got != c.label {
			t.Errorf("%s %s: label %q, want %q", c.method, c.path, got, c.label)
		}
		ok, why := c.scope.Allow(r)
		if ok != c.ok {
			t.Errorf("%s %s under %+v: allowed %v, want %v (%s)", c.method, c.path, c.scope, ok, c.ok, why)
		}
		if c.why != "" && !strings.Contains(why, c.why) {
			t.Errorf("%s %s: said %q, want it to say %q", c.method, c.path, why, c.why)
		}
		if c.ok && why != "" {
			t.Errorf("%s %s: allowed with a reason %q", c.method, c.path, why)
		}
	}
}

// Outside the API nothing is forwarded: the proxy answers 404.
func TestGuardRefusesWhatIsNotTheAPI(t *testing.T) {
	for _, p := range []string{"", "/", "/healthz", "/metrics", "/apis/../api/v1/pods", "/api//v1/pods", "/foo/bar", "/.well-known/openid-configuration"} {
		if _, ok := Parse("GET", p, nil); ok {
			t.Errorf("%q: read as an API path", p)
		}
	}
}
