// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// get fetches url with client and returns the error, wrapped as the
// directory sync wraps it.
func get(t *testing.T, client *http.Client, u string) error {
	t.Helper()
	resp, err := client.Get(u) // #nosec G107 -- a test server's address
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("GET %s succeeded", u)
	}
	return fmt.Errorf("list the directory: discovery: %w", err)
}

// TestPlainErrorSaysWhyTheProviderIsUnreachable: a provider the gateway
// cannot reach is named by host with what happened, in words, however
// deeply the call wrapped the error: no answer in time (the live console's
// case, 2026-11-02), a refused connection, a name that does not resolve, an
// untrusted certificate. Nothing of the call chain shows.
func TestPlainErrorSaysWhyTheProviderIsUnreachable(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer slow.Close()
	slowHost := strings.TrimPrefix(slow.URL, "http://")
	timeout := get(t, &http.Client{Timeout: 100 * time.Millisecond}, slow.URL+"/realms/zanskar/.well-known/openid-configuration")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	refused := get(t, &http.Client{Timeout: 2 * time.Second}, "http://"+closed+"/")

	tlsSrv := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsSrv.Close()
	untrusted := get(t, &http.Client{Timeout: 2 * time.Second}, tlsSrv.URL+"/")

	noName := fmt.Errorf("discovery: %w", &url.Error{Op: "Get", URL: "https://kc.example/realms/z/.well-known/openid-configuration",
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "kc.example", IsNotFound: true}}})

	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"no answer in time", timeout, "could not reach " + slowHost + ": it did not answer in time"},
		{"refused", refused, "could not reach " + closed + ": it refused the connection"},
		{"untrusted certificate", untrusted, "could not reach " + strings.TrimPrefix(tlsSrv.URL, "https://") + ": its certificate is not trusted (certificate signed by unknown authority)"},
		{"no such name", noName, "could not reach kc.example: the name does not resolve from the gateway"},
		{"a deadline with no request", fmt.Errorf("list the directory: %w", context.DeadlineExceeded), "could not reach the provider: it did not answer in time"},
	} {
		if got := PlainError(c.err); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q\n(from %v)", c.name, got, c.want, c.err)
		}
	}
}

// TestPlainErrorKeepsOtherWords: an answer from the provider (a refusal of
// the client, a status) is not a failure to reach it and keeps its words.
func TestPlainErrorKeepsOtherWords(t *testing.T) {
	for _, msg := range []string{"keycloak admin API refused the client (HTTP 403)", "discovery: 404 Not Found: realm does not exist"} {
		if got := PlainError(errors.New(msg)); got != msg {
			t.Errorf("%q became %q", msg, got)
		}
	}
	if PlainError(nil) != "" {
		t.Error("no error, no words")
	}
}

// TestSyncFailureInPlainWords: a sync that cannot reach the provider keeps
// the plain words in its status, which the console shows, and in its audit
// event; the chain of calls is for the log.
func TestSyncFailureInPlainWords(t *testing.T) {
	e := newSyncEnv(t, nil)
	e.dir.err = fmt.Errorf("discovery: %w", &url.Error{Op: "Get", URL: "https://keycloak.techmanship.in/realms/zanskar/.well-known/openid-configuration",
		Err: context.DeadlineExceeded})
	st, err := e.s.Sync(context.Background(), e.op, SyncOptions{Manual: true})
	want := "could not reach keycloak.techmanship.in: it did not answer in time"
	if err == nil || st.Error != want {
		t.Fatalf("status error %q (%v), want %q", st.Error, err, want)
	}
	evs := e.events(t, "idp.sync")
	if len(evs) == 0 || evs[0]["error"] != want {
		t.Fatalf("audit: %v", evs)
	}
}
