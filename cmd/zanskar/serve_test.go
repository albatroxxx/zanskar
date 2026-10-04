// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// freeAddr returns a loopback address with a port nothing is listening on.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestServeStartsAndStops runs the whole gateway as `zanskar serve` would,
// against a migrated install with one admin: it becomes ready, answers its
// health checks and the API (a sign-in reaches the second-factor step, an
// unknown API path is a JSON 404), and stops cleanly when its context ends.
func TestServeStartsAndStops(t *testing.T) {
	newCLIGateway(t, true)
	addr := freeAddr(t)
	t.Setenv("ZANSKAR_LISTEN_ADDR", addr)
	t.Setenv("ZANSKAR_LOG_LEVEL", "error")
	t.Setenv("ZANSKAR_REQUIRE_MFA", "true")
	t.Setenv("ZANSKAR_ADMIN_PASSWORD", "a long enough passphrase 42")
	if _, _, err := output(t, func() error { return runAdmin([]string{"create", "-username", "root", "-name", "Root"}) }); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx) }()

	base := "http://" + addr
	client := &http.Client{Timeout: 2 * time.Second}
	ready := false
	for i := 0; i < 200 && !ready; i++ {
		select {
		case err := <-done:
			t.Fatalf("serve stopped early: %v", err)
		default:
		}
		if resp, err := client.Get(base + "/readyz"); err == nil {
			ready = resp.StatusCode == http.StatusOK
			_ = resp.Body.Close()
		}
		if !ready {
			time.Sleep(25 * time.Millisecond)
		}
	}
	if !ready {
		t.Fatal("gateway never became ready")
	}

	get := func(path string) (int, string) {
		t.Helper()
		resp, err := client.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var b bytes.Buffer
		_, _ = b.ReadFrom(resp.Body)
		return resp.StatusCode, b.String()
	}
	if code, _ := get("/healthz"); code != http.StatusOK {
		t.Fatalf("healthz: %d", code)
	}
	if code, body := get("/api/v1/no-such-route"); code != http.StatusNotFound || !strings.Contains(body, `"code"`) {
		t.Fatalf("unknown API path: %d %s", code, body)
	}
	if code, body := get("/api/v1/system/banner"); code != http.StatusOK || !strings.Contains(body, `"text"`) {
		t.Fatalf("public banner: %d %s", code, body)
	}

	login, _ := json.Marshal(map[string]string{"username": "root", "password": "a long enough passphrase 42"})
	resp, err := client.Post(base+"/api/v1/auth/login", "application/json", bytes.NewReader(login))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || out["status"] != "mfa_enrollment_required" {
		t.Fatalf("sign-in: %d %v", resp.StatusCode, out)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve after its context ended: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop when its context ended")
	}
}

// TestServeRefusesPendingMigrations: migrations are an explicit operator
// step, never a side effect of starting.
func TestServeRefusesPendingMigrations(t *testing.T) {
	newCLIGateway(t, false)
	t.Setenv("ZANSKAR_LISTEN_ADDR", freeAddr(t))
	t.Setenv("ZANSKAR_LOG_LEVEL", "error")
	err := serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "zanskar migrate") {
		t.Fatalf("got %v, want a refusal naming `zanskar migrate`", err)
	}
}
