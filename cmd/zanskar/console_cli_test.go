// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// cliClient is a signed-in administrator talking to a real gateway.
type cliClient struct {
	t    *testing.T
	base string
	http *http.Client
	csrf string
}

func (c *cliClient) call(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(c.t.Context(), method, c.base+path, rdr)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// run sends one command line and returns the reply's status, its text and
// the word a confirmation expects.
func (c *cliClient) run(line, confirm string) (string, string, string) {
	c.t.Helper()
	code, out := c.call("POST", "/api/v1/admin/cli", map[string]string{"line": line, "confirm": confirm})
	if code != http.StatusOK {
		c.t.Fatalf("%q: HTTP %d %v", line, code, out)
	}
	var text []string
	lines, _ := out["lines"].([]any)
	for _, l := range lines {
		m, _ := l.(map[string]any)
		s, _ := m["text"].(string)
		text = append(text, s)
	}
	status, _ := out["status"].(string)
	expect, _ := out["expect"].(string)
	return status, strings.Join(text, "\n"), expect
}

// TestConsoleCLIEndToEnd drives the command line against a real gateway: the
// commands reach the real routes, read their real replies, ask before
// destructive changes, refuse shell syntax and leave an audit trail.
func TestConsoleCLIEndToEnd(t *testing.T) {
	newCLIGateway(t, true)
	addr := freeAddr(t)
	t.Setenv("ZANSKAR_LISTEN_ADDR", addr)
	t.Setenv("ZANSKAR_LOG_LEVEL", "error")
	t.Setenv("ZANSKAR_REQUIRE_MFA", "true")
	t.Setenv("ZANSKAR_CONSOLE_CLI", "")
	t.Setenv("ZANSKAR_ADMIN_PASSWORD", "a long enough passphrase 42")
	if _, _, err := output(t, func() error { return runAdmin([]string{"create", "-username", "root", "-name", "Root"}) }); err != nil {
		t.Fatal(err)
	}
	base, _, cancel := startServe(t, addr)
	defer cancel()
	jar, _ := cookiejar.New(nil)
	c := &cliClient{t: t, base: base, http: &http.Client{Timeout: 10 * time.Second, Jar: jar}}

	// Sign in and enrol an authenticator; confirming it proves a code.
	code, out := c.call("POST", "/api/v1/auth/login", map[string]string{"username": "root", "password": "a long enough passphrase 42"})
	if code != http.StatusOK {
		t.Fatalf("login: %d %v", code, out)
	}
	c.csrf, _ = out["csrf_token"].(string)
	if code, out = c.call("POST", "/api/v1/auth/mfa/totp/enroll", nil); code != http.StatusOK {
		t.Fatalf("enroll: %d %v", code, out)
	}
	secret, _ := out["secret"].(string)
	now, _ := totp.GenerateCode(secret, time.Now())
	if code, out = c.call("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": now}); code != http.StatusOK {
		t.Fatalf("confirm: %d %v", code, out)
	}
	if code, out = c.call("GET", "/api/v1/admin/cli", nil); code != http.StatusOK || out["unlocked"] != true || out["mfa_enrolled"] != true {
		t.Fatalf("cli state after a fresh code: %d %v", code, out)
	}
	if code, out = c.call("POST", "/api/v1/admin/cli/unlock", map[string]string{"code": "000000"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong unlock code: %d %v", code, out)
	}
	if code, out = c.call("POST", "/api/v1/admin/cli/unlock", map[string]string{"code": now}); code != http.StatusOK {
		t.Fatalf("unlock: %d %v", code, out)
	}

	// Something to look at.
	if code, out = c.call("POST", "/api/v1/users", map[string]any{"username": "alice", "display_name": "Alice Moreau", "email": "alice@example.test", "password": "alice temporary pw 1", "roles": []string{"user"}}); code != http.StatusCreated {
		t.Fatalf("create alice: %d %v", code, out)
	}
	if code, out = c.call("POST", "/api/v1/targets", map[string]any{"name": "web-01", "address": "10.20.0.5", "os_family": "linux", "tags": map[string]string{"env": "prod"}}); code != http.StatusCreated {
		t.Fatalf("create target: %d %v", code, out)
	}

	expectOK := func(line string, want ...string) string {
		t.Helper()
		status, text, _ := c.run(line, "")
		if status != "ok" {
			t.Fatalf("%q: status %s\n%s", line, status, text)
		}
		for _, w := range want {
			if !strings.Contains(text, w) {
				t.Fatalf("%q: output lacks %q\n%s", line, w, text)
			}
		}
		return text
	}
	expectOK("status", "chain verified", "0 live")
	expectOK("version", "Zanskar")
	expectOK("help", "user disable", "audit verify", "not a shell")
	expectOK("help user disable", "Asks you to confirm", "Example: user disable alice")
	if text := expectOK("users --role admin", "root"); strings.Contains(text, "alice") {
		t.Fatalf("--role admin listed alice:\n%s", text)
	}
	expectOK("users", "alice", "Alice Moreau")
	expectOK("user show alice", "alice@example.test", "active")
	expectOK("targets --tag env=prod", "web-01", "10.20.0.5")
	expectOK("target show web-01", "10.20.0.5", "env=prod")
	expectOK("sessions --live", "(none)")
	expectOK("requests --pending", "(none)")
	expectOK("policies", "(none)")
	expectOK("asgs", "(none)")
	expectOK("logs --last 3")
	expectOK("tls", "mode")
	expectOK("storage", "stored in")
	expectOK("settings", "log.level")
	expectOK("audit verify", "Chain intact")

	// A destructive command asks first, re-checks, and runs only on the
	// exact word.
	status, text, expect := c.run("user disable alice", "")
	if status != "confirm" || expect != "alice" || !strings.Contains(text, "stops alice signing in") {
		t.Fatalf("disable prompt: %s %q\n%s", status, expect, text)
	}
	if status, _, _ = c.run("user disable alice", "Alice"); status != "cancelled" {
		t.Fatalf("a wrong word must cancel, got %s", status)
	}
	if status, text, _ = c.run("user disable alice", "alice"); status != "error" || !strings.Contains(text, "Nothing to confirm") {
		t.Fatalf("a cancelled prompt must not stay answerable: %s\n%s", status, text)
	}
	c.run("user disable alice", "")
	if status, text, _ = c.run("user disable alice", "alice"); status != "ok" {
		t.Fatalf("confirmed disable: %s\n%s", status, text)
	}
	expectOK("user show alice", "disabled", "alice@example.test") // the email survived the PUT
	expectOK("user enable alice", "active")

	c.run("setting set log.level debug", "")
	if status, text, _ = c.run("setting set log.level debug", "log.level"); status != "ok" {
		t.Fatalf("setting set: %s\n%s", status, text)
	}
	expectOK("setting get log.level", "debug", "console")

	// What is refused, and how.
	for line, want := range map[string]string{
		"rm -rf /var/lib/zanskar": "This is not a shell",
		"users | grep alice":      "not a shell",
		"user show ../../admin":   "is not a valid",
		"user show nobody":        `No user named "nobody"`,
		"users --colour":          "has no option --colour",
		"restart cancel":          "No restart is waiting",
		"user disable root":       "",
	} {
		status, text, _ = c.run(line, "")
		if line == "user disable root" {
			// Asks first; the API then refuses an administrator disabling
			// themselves, and the command line says why.
			if status, text, _ = c.run(line, "root"); status != "error" || !strings.Contains(text, "your own account") {
				t.Fatalf("self-disable: %s\n%s", status, text)
			}
			continue
		}
		if status != "error" || !strings.Contains(text, want) {
			t.Fatalf("%q: %s\n%s", line, status, text)
		}
	}

	// Every line is in the audit log, with the routes it called.
	code, out = c.call("GET", "/api/v1/audit/events?action=cli.command&limit=200", nil)
	if code != http.StatusOK {
		t.Fatalf("events: %d %v", code, out)
	}
	items, _ := out["items"].([]any)
	var sawDisable, sawUnknown bool
	for _, it := range items {
		d, _ := it.(map[string]any)["details"].(map[string]any)
		switch {
		case d["line"] == "user disable alice" && d["result"] == "ok":
			b, _ := json.Marshal(d["calls"])
			sawDisable = strings.Contains(string(b), `"method":"PUT"`)
		case d["line"] == "rm -rf /var/lib/zanskar" && d["result"] == "unknown":
			sawUnknown = true
		}
	}
	if !sawDisable || !sawUnknown {
		t.Fatalf("audit trail incomplete (disable with PUT %v, unknown %v) in %d events", sawDisable, sawUnknown, len(items))
	}
	expectOK("events --action cli.unlock --last 5", "cli.unlock")
}

// TestConsoleCLIOff: with ZANSKAR_CONSOLE_CLI=off the routes do not exist.
func TestConsoleCLIOff(t *testing.T) {
	newCLIGateway(t, true)
	addr := freeAddr(t)
	t.Setenv("ZANSKAR_LISTEN_ADDR", addr)
	t.Setenv("ZANSKAR_LOG_LEVEL", "error")
	t.Setenv("ZANSKAR_CONSOLE_CLI", "off")
	base, _, cancel := startServe(t, addr)
	defer cancel()
	c := &cliClient{t: t, base: base, http: &http.Client{Timeout: 5 * time.Second}}
	if code, _ := c.call("GET", "/api/v1/admin/cli", nil); code != http.StatusNotFound {
		t.Fatalf("GET /admin/cli with the command line off: %d, want 404", code)
	}
}

// TestConsoleCLINeedsAProvedCode: where an authenticator is not required, an
// administrator can get a working console session without ever entering a
// code: by signing in, or by replacing a password another administrator set.
// Neither proves a code, so the command line stays shut.
func TestConsoleCLINeedsAProvedCode(t *testing.T) {
	newCLIGateway(t, true)
	addr := freeAddr(t)
	t.Setenv("ZANSKAR_LISTEN_ADDR", addr)
	t.Setenv("ZANSKAR_LOG_LEVEL", "error")
	t.Setenv("ZANSKAR_REQUIRE_MFA", "false")
	t.Setenv("ZANSKAR_CONSOLE_CLI", "")
	t.Setenv("ZANSKAR_ADMIN_PASSWORD", "a long enough passphrase 42")
	if _, _, err := output(t, func() error { return runAdmin([]string{"create", "-username", "root", "-name", "Root"}) }); err != nil {
		t.Fatal(err)
	}
	base, _, cancel := startServe(t, addr)
	defer cancel()
	signIn := func(name, password string) (*cliClient, map[string]any) {
		jar, _ := cookiejar.New(nil)
		c := &cliClient{t: t, base: base, http: &http.Client{Timeout: 10 * time.Second, Jar: jar}}
		code, out := c.call("POST", "/api/v1/auth/login", map[string]string{"username": name, "password": password})
		if code != http.StatusOK {
			t.Fatalf("login %s: %d %v", name, code, out)
		}
		c.csrf, _ = out["csrf_token"].(string)
		return c, out
	}
	locked := func(c *cliClient, who string) {
		t.Helper()
		if code, out := c.call("GET", "/api/v1/users", nil); code != http.StatusOK {
			t.Fatalf("%s: the console session should work: %d %v", who, code, out)
		}
		if code, out := c.call("POST", "/api/v1/admin/cli", map[string]string{"line": "users"}); code != http.StatusForbidden || out["code"] != "cli_locked" {
			t.Fatalf("%s: a command with no proved code: %d %v", who, code, out)
		}
	}

	root, out := signIn("root", "a long enough passphrase 42")
	if out["status"] != "ok" {
		t.Fatalf("root signs in with no authenticator: %v", out)
	}
	locked(root, "root after sign-in")
	if code, out := root.call("POST", "/api/v1/admin/cli/unlock", map[string]string{"code": "123456"}); code != http.StatusConflict || out["code"] != "mfa_not_enrolled" {
		t.Fatalf("unlock with no authenticator: %d %v", code, out)
	}

	// A second administrator whose first password root chose.
	if code, out := root.call("POST", "/api/v1/users", map[string]any{"username": "ops", "display_name": "Ops", "password": "ops temporary pw 1", "roles": []string{"admin"}}); code != http.StatusCreated {
		t.Fatalf("create ops: %d %v", code, out)
	}
	ops, _ := signIn("ops", "ops temporary pw 1")
	if code, out := ops.call("POST", "/api/v1/auth/password", map[string]string{"current_password": "ops temporary pw 1", "new_password": "ops chose this passphrase"}); code != http.StatusOK || out["status"] != "ok" {
		t.Fatalf("ops replaces the password: %d %v", code, out)
	}
	locked(ops, "ops after replacing the password")
}
