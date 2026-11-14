// SPDX-License-Identifier: Apache-2.0

package kubegw

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// Request is one API request as the guard-rail reads it (ADR 0045, 4): the
// resource it names, where, and what it does to it. The API's paths have two
// shapes, /api/{version}/... for the core group and /apis/{group}/{version}/...
// for the rest, each followed by [namespaces/{ns}/]{resource}[/{name}[/{sub}]].
type Request struct {
	// Discovery is a request for what the API offers (/api, /apis and their
	// group and version lists, /version, /openapi): allowed to every session,
	// since kubectl cannot work without it, and not recorded.
	Discovery bool
	Group     string
	Version   string
	// Namespace is empty for a cluster-wide request: a cluster-scoped
	// resource, or a list across namespaces (kubectl get pods -A).
	Namespace   string
	Resource    string
	Name        string
	Subresource string
	// Rest is what follows the subresource, a proxy's path for one.
	Rest string
	// Verb is the API's word for what the request does: get, list, watch,
	// create, update, patch, delete, deletecollection; for a stream, exec,
	// attach, portforward, log, proxy.
	Verb string
}

// Scope is what a session may reach (policy.KubeScope, in this package's
// terms so it needs no import of the policy).
type Scope struct {
	Namespaces   []string
	ClusterScope bool
	PortForward  bool
}

// Covers reports whether the scope admits a request in ns.
func (s Scope) Covers(ns string) bool {
	return len(s.Namespaces) == 0 || slices.Contains(s.Namespaces, ns)
}

// Parse reads an API path (cleaned, with the gateway's prefix removed) and
// the request's method and query into a Request. ok is false for a path
// outside the API: the proxy answers 404 and forwards nothing.
func Parse(method, path string, query url.Values) (Request, bool) {
	path = strings.Trim(path, "/")
	segs := strings.Split(path, "/")
	if path == "" {
		return Request{}, false
	}
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return Request{}, false
		}
	}
	var r Request
	rest := segs
	switch segs[0] {
	case "version", "openapi":
		return Request{Discovery: true, Verb: "get"}, true
	case "api":
		// /api, /api/v1, /api/v1/...
		if len(segs) <= 2 {
			return Request{Discovery: true, Verb: "get"}, true
		}
		r.Version = segs[1]
		rest = segs[2:]
	case "apis":
		// /apis, /apis/{group}, /apis/{group}/{version}, /apis/{group}/{version}/...
		if len(segs) <= 3 {
			return Request{Discovery: true, Verb: "get"}, true
		}
		r.Group, r.Version = segs[1], segs[2]
		rest = segs[3:]
	default:
		return Request{}, false
	}
	// A namespaced path names the namespace first; the namespaces resource
	// itself is cluster-scoped, so /namespaces/{ns} alone is a request for
	// that namespace's object, read as a request in it (kubectl get ns prod).
	if rest[0] == "namespaces" && len(rest) >= 3 {
		r.Namespace = rest[1]
		rest = rest[2:]
	} else if rest[0] == "namespaces" && len(rest) == 2 {
		r.Namespace, r.Resource, r.Name = rest[1], "namespaces", rest[1]
		rest = nil
	}
	if len(rest) > 0 {
		r.Resource = rest[0]
		rest = rest[1:]
	}
	if len(rest) > 0 {
		r.Name = rest[0]
		rest = rest[1:]
	}
	if len(rest) > 0 {
		r.Subresource = rest[0]
		rest = rest[1:]
	}
	if len(rest) > 0 {
		r.Rest = strings.Join(rest, "/")
	}
	r.Verb = verb(method, r, query)
	return r, true
}

// verb is the API's word for the request.
func verb(method string, r Request, q url.Values) string {
	switch r.Subresource {
	case "exec", "attach", "portforward", "log", "proxy":
		return r.Subresource
	}
	switch method {
	case http.MethodGet, http.MethodHead:
		if q.Get("watch") == "true" || q.Get("watch") == "1" {
			return "watch"
		}
		if r.Name == "" {
			return "list"
		}
		return "get"
	case http.MethodPost:
		return "create"
	case http.MethodPut:
		return "update"
	case http.MethodPatch:
		return "patch"
	case http.MethodDelete:
		if r.Name == "" {
			return "deletecollection"
		}
		return "delete"
	}
	return strings.ToLower(method)
}

// Allow says whether the scope admits the request; when it does not, the
// sentence the person is told, which names what the access covers.
func (s Scope) Allow(r Request) (ok bool, why string) {
	if r.Discovery {
		return true, ""
	}
	if r.Verb == "portforward" && !s.PortForward {
		return false, "Zanskar: your access to this cluster does not include port-forward"
	}
	if r.SelfReview() {
		// kubectl auth whoami and auth can-i ask about the caller alone,
		// at paths that name no namespace; the cluster answers for the
		// person impersonated. Recorded, as any request is.
		return true, ""
	}
	if r.Namespace == "" {
		if s.ClusterScope {
			return true, ""
		}
		if len(s.Namespaces) == 0 {
			return false, "Zanskar: your access to this cluster covers namespaced resources only; name a namespace (-n)"
		}
		return false, "Zanskar: your access to this cluster covers the namespaces " + strings.Join(s.Namespaces, ", ") + " only; name one (-n)"
	}
	if !s.Covers(r.Namespace) {
		return false, "Zanskar: your access to this cluster covers the namespaces " + strings.Join(s.Namespaces, ", ") + " only, not " + r.Namespace
	}
	return true, ""
}

// SelfReview reports whether the request is one of the API's reviews of the
// caller's own identity or access (SelfSubjectReview, SelfSubjectAccessReview,
// SelfSubjectRulesReview): about the person and nothing else, so every scope
// admits it (kind v1.37, 2026-11-14: auth whoami and auth can-i were refused
// as cluster-wide).
func (r Request) SelfReview() bool {
	switch {
	case r.Group == "authentication.k8s.io" && r.Resource == "selfsubjectreviews":
		return true
	case r.Group == "authorization.k8s.io" && (r.Resource == "selfsubjectaccessreviews" || r.Resource == "selfsubjectrulesreviews"):
		return true
	}
	return false
}

// Label is the request as the recording and the live watcher show it:
// "{verb} {resource}[/{name}] [-n {ns}]", the words kubectl uses.
func (r Request) Label() string {
	var b strings.Builder
	b.WriteString(r.Verb)
	if r.Resource != "" {
		b.WriteByte(' ')
		b.WriteString(r.Resource)
		if r.Name != "" && r.Resource != "namespaces" {
			b.WriteByte('/')
			b.WriteString(r.Name)
		}
	}
	if r.Namespace != "" {
		b.WriteString(" -n ")
		b.WriteString(r.Namespace)
	}
	return b.String()
}
