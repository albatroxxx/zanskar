// SPDX-License-Identifier: Apache-2.0

// Package kubetest is a Kubernetes API server for tests: it checks the
// bearer token, answers what the client and the proxy ask, streams a watch,
// echoes an upgraded stream, and keeps what it was asked so a test can look
// at the headers the gateway sent.
package kubetest

import (
	"bufio"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Request is one request as the fake received it.
type Request struct {
	Method, Path, Query string
	Header              http.Header
	Proto               string
}

// API is the fake. Set the fields before Start; the rest is read after.
type API struct {
	// Token is the bearer token the fake accepts; anything else is 401.
	Token string
	// Allow says, per resource, whether impersonation is allowed in access reviews.
	Allow map[string]bool
	// NSDeny makes the namespace list 403.
	NSDeny bool
	// Version is what /version answers.
	Version string
	// WatchEvents is how many events a watch streams before it holds the
	// connection open; 0 holds at once.
	WatchEvents int

	mu   sync.Mutex
	reqs []Request
}

// Requests returns every request received so far.
func (f *API) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.reqs...)
}

// Last returns the last request received.
func (f *API) Last() Request {
	rs := f.Requests()
	if len(rs) == 0 {
		return Request{}
	}
	return rs[len(rs)-1]
}

// Count returns how many requests were received.
func (f *API) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func (f *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.reqs = append(f.reqs, Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Header: r.Header.Clone(), Proto: r.Proto})
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.Token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == "/version":
		_ = json.NewEncoder(w).Encode(map[string]string{"gitVersion": f.Version, "platform": "linux/amd64"})
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
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]bool{"allowed": in.Spec.ResourceAttributes.Verb == "impersonate" && f.Allow[in.Spec.ResourceAttributes.Resource]}})
	case r.URL.Path == "/api/v1/namespaces" && r.URL.Query().Get("watch") == "":
		if f.NSDeny {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{"metadata": map[string]string{"name": "default"}}, {"metadata": map[string]string{"name": "prod"}}}})
	case r.Header.Get("Upgrade") != "":
		f.echo(w, r)
	case r.URL.Query().Get("watch") == "true":
		f.watch(w, r)
	case r.URL.Path == "/api" || r.URL.Path == "/apis" || strings.Count(r.URL.Path, "/") <= 2:
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": "APIVersions", "versions": []string{"v1"}})
	default:
		// Any resource: an empty list or an object, with the path echoed so
		// a test can see what reached the cluster.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": "List", "apiVersion": "v1", "metadata": map[string]any{"path": r.URL.Path}, "items": []any{}})
	}
}

// watch streams WatchEvents lines, flushing each, then holds the connection
// until the client goes.
func (f *API) watch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	for i := range f.WatchEvents {
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "ADDED", "object": map[string]any{"metadata": map[string]any{"name": "ev-" + string(rune('a'+i))}}})
		if fl != nil {
			fl.Flush()
		}
		time.Sleep(10 * time.Millisecond)
	}
	<-r.Context().Done()
}

// echo answers an upgrade with 101 and echoes every byte back, as a pod's
// shell would answer what it is typed.
func (f *API) echo(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+r.Header.Get("Upgrade")+"\r\n\r\n")
	rd := bufio.NewReader(brw)
	buf := make([]byte, 4096)
	for {
		n, err := rd.Read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// Start serves the fake over TLS, HTTP/2 offered (the gateway must still
// speak 1.1), and returns its URL and its certificate as a PEM bundle.
func Start(t testing.TB, f *API) (apiServer, caPEM string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(f)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	return srv.URL, ca
}

// Dial opens a raw connection to the fake, for a test that speaks the wire.
func Dial(t testing.TB, apiServer string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(apiServer, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
