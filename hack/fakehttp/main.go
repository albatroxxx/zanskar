// SPDX-License-Identifier: Apache-2.0

// Command fakehttp is a toy web application for the browser suite and the
// smoke test: it answers every request with a page that shows the request
// as the application saw it, so a test can prove what the gateway's proxy
// forwarded and what it kept back (the console cookie, identity headers).
// Listen address as the one argument, like fakessh.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// origin is the address the application believes it is served at, set at
// start: /redirect sends the browser there, the way an application with a
// configured base URL does, and never to anything taken from a request.
var origin string

func main() {
	flag.StringVar(&origin, "origin", "", "the application's own origin, such as http://10.0.0.5:8083; /redirect points at it")
	flag.Parse()
	addr := "127.0.0.1:8083"
	if flag.NArg() > 0 {
		addr = flag.Arg(0)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr) // #nosec G102 -- dev tool: it must be reached from the gateway by the LAN address, as a real application would
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "fakehttp listening on", ln.Addr())
	srv := &http.Server{Handler: http.HandlerFunc(serve), ReadHeaderTimeout: 5 * time.Second}
	if err := srv.Serve(ln); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// seen is the request as the application received it.
type seen struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Host    string              `json:"host"`
	Headers map[string][]string `json:"headers"`
}

func serve(w http.ResponseWriter, r *http.Request) {
	s := seen{Method: r.Method, Path: r.URL.RequestURI(), Host: r.Host, Headers: map[string][]string{}}
	for k, v := range r.Header {
		s.Headers[k] = v
	}
	fmt.Fprintf(os.Stderr, "%s %s host=%s cookie=%q\n", r.Method, r.URL.RequestURI(), r.Host, r.Header.Get("Cookie"))
	if r.URL.Path == "/headers" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s)
		return
	}
	if r.URL.Path == "/redirect" {
		// A redirect to the application's own origin, as configured at start,
		// which the proxy under test must rewrite onto the address the
		// browser used. Nothing from the request goes into the Location.
		if origin == "" {
			http.Error(w, "fakehttp was started without -origin", http.StatusNotImplemented)
			return
		}
		w.Header().Set("Location", origin+"/landed")
		w.WriteHeader(http.StatusFound)
		return
	}
	keys := make([]string, 0, len(s.Headers))
	for k := range s.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\n", html.EscapeString(k), html.EscapeString(strings.Join(s.Headers[k], ", ")))
	}
	js, _ := json.Marshal(s)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><title>fakehttp</title></head><body>
<h1>fakehttp</h1><p id="path">%s %s on %s</p>
<pre id="headers">%s</pre><script type="application/json" id="seen">%s</script>
</body></html>`, html.EscapeString(r.Method), html.EscapeString(r.URL.RequestURI()), html.EscapeString(r.Host), b.String(), js)
}
