// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestServeManagedTLSAndRedirect is a first start in managed-TLS mode: the
// gateway makes its own certificate, serves HTTPS with it, and its plain-HTTP
// listener redirects to HTTPS on the same path. The certificate covers the
// address the gateway listens on. A Host header naming somewhere else is not
// followed: the redirect goes to a name the certificate covers, so the
// listener cannot be used to bounce browsers to another site.
func TestServeManagedTLSAndRedirect(t *testing.T) {
	newCLIGateway(t, true)
	addr, plain := freeAddr(t), freeAddr(t)
	t.Setenv("ZANSKAR_TLS_MODE", "managed")
	t.Setenv("ZANSKAR_LISTEN_ADDR", addr)
	t.Setenv("ZANSKAR_HTTP_REDIRECT_ADDR", plain)
	t.Setenv("ZANSKAR_LOG_LEVEL", "error")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx) }()

	// The test checks the certificate itself below, so it accepts it here.
	tlsClient := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}} // #nosec G402 -- the certificate is verified explicitly below
	var resp *http.Response
	for i := 0; i < 200; i++ {
		select {
		case err := <-done:
			t.Fatalf("serve stopped early: %v", err)
		default:
		}
		var err error
		if resp, err = tlsClient.Get("https://" + addr + "/readyz"); err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		resp = nil
		time.Sleep(25 * time.Millisecond)
	}
	if resp == nil {
		t.Fatal("the gateway never answered over HTTPS")
	}
	_ = resp.Body.Close()
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("no certificate presented")
	}
	if err := resp.TLS.PeerCertificates[0].VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("the managed certificate does not cover the listen address: %v", err)
	}

	noFollow := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	redirectOf := func(host string) string {
		t.Helper()
		req, _ := http.NewRequest("GET", "http://"+plain+"/admin/targets?x=1", nil)
		if host != "" {
			req.Host = host
		}
		r, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != http.StatusMovedPermanently {
			t.Fatalf("plain HTTP answered %d, want 301", r.StatusCode)
		}
		return r.Header.Get("Location")
	}
	if loc := redirectOf(""); loc != "https://"+addr+"/admin/targets?x=1" {
		t.Fatalf("redirect to %q", loc)
	}
	if loc := redirectOf("evil.example"); strings.Contains(loc, "evil.example") {
		t.Fatalf("the redirect followed a foreign Host header: %q", loc)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve after its context ended: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop")
	}
}
