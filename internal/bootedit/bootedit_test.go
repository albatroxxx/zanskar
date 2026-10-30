// SPDX-License-Identifier: Apache-2.0

package bootedit_test

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/bootedit"
	"github.com/albatroxxx/zanskar/internal/lifecycle"
)

// TestChangesRefusesWhatIsNotTheConsoles (ADR 0020, amended 2026-10-30):
// the request comes from a process an attacker may control. Anything
// outside the allowlist, a preset's variable on its own, or a value that
// could break out of its line refuses the whole request; a hostile name is
// not repeated back.
func TestChangesRefusesWhatIsNotTheConsoles(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  bootedit.Request
	}{
		{"database", bootedit.Request{Values: map[string]string{"ZANSKAR_DB_DSN": "postgres://evil"}}},
		{"master key", bootedit.Request{Values: map[string]string{"ZANSKAR_MASTER_KEY": "AAAA"}}},
		{"container runtime", bootedit.Request{Values: map[string]string{"ZANSKAR_DOCKER_PATH": "/tmp/x"}}},
		{"listen address on its own", bootedit.Request{Values: map[string]string{"ZANSKAR_LISTEN_ADDR": "0.0.0.0:22"}}},
		{"proxy trust", bootedit.Request{Values: map[string]string{"ZANSKAR_TRUSTED_PROXIES": "0.0.0.0/0"}}},
		{"preset plus its own key", bootedit.Request{TLSMode: "managed", Values: map[string]string{"ZANSKAR_TLS_MODE": "proxy"}}},
		{"unknown preset", bootedit.Request{TLSMode: "file"}},
		{"newline", bootedit.Request{Values: map[string]string{"ZANSKAR_ISSUER": "Acme\nZANSKAR_DB_DSN=x"}}},
		{"NUL", bootedit.Request{Values: map[string]string{"ZANSKAR_ISSUER": "Acme\x00"}}},
		{"quote", bootedit.Request{Values: map[string]string{"ZANSKAR_ISSUER": `Acme"`}}},
		{"backslash", bootedit.Request{Values: map[string]string{"ZANSKAR_ISSUER": `Acme\`}}},
		{"dollar", bootedit.Request{Values: map[string]string{"ZANSKAR_ISSUER": "$HOME"}}},
		{"cap", bootedit.Request{Values: map[string]string{"ZANSKAR_APPS_MAX_SESSIONS": "-1"}}},
		{"cap text", bootedit.Request{Values: map[string]string{"ZANSKAR_APPS_MAX_SESSIONS": "ten"}}},
		{"http URL", bootedit.Request{Values: map[string]string{"ZANSKAR_PUBLIC_URL": "http://gw.example.com"}}},
		{"URL with a path", bootedit.Request{Values: map[string]string{"ZANSKAR_PUBLIC_URL": "https://gw.example.com/admin"}}},
		{"URL with a user", bootedit.Request{Values: map[string]string{"ZANSKAR_PUBLIC_URL": "https://a@gw.example.com"}}},
		{"bad host", bootedit.Request{Values: map[string]string{"ZANSKAR_TLS_HOSTS": "gw.example.com,bad host"}}},
		{"log format", bootedit.Request{Values: map[string]string{"ZANSKAR_LOG_FORMAT": "xml"}}},
		{"principal", bootedit.Request{Values: map[string]string{"ZANSKAR_AWS_GATEWAY_PRINCIPAL": "anyone"}}},
		{"nothing", bootedit.Request{}},
	} {
		if _, err := bootedit.Changes(tc.req); !errors.Is(err, bootedit.ErrInvalid) {
			t.Errorf("%s: accepted (%v)", tc.name, err)
		}
	}
	_, err := bootedit.Changes(bootedit.Request{Values: map[string]string{"ZANSKAR_X\n<script>": "1"}})
	if err == nil || strings.Contains(err.Error(), "<script>") {
		t.Fatalf("a hostile name was repeated: %v", err)
	}
}

func TestChangesTakesTheAllowlistAndThePresets(t *testing.T) {
	got, err := bootedit.Changes(bootedit.Request{TLSMode: "managed", Values: map[string]string{
		"ZANSKAR_PUBLIC_URL": " https://zanskar.example.com ", "ZANSKAR_TLS_HOSTS": "zanskar.example.com, 203.0.113.7",
		"ZANSKAR_ISSUER": "Acme O'Brien Ltd", "ZANSKAR_APPS_MAX_SESSIONS": "0", "ZANSKAR_AWS_GATEWAY_PRINCIPAL": "",
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"ZANSKAR_TLS_MODE": "managed", "ZANSKAR_LISTEN_ADDR": ":443", "ZANSKAR_HTTP_REDIRECT_ADDR": ":80", "ZANSKAR_TRUST_PROXY_TLS": "false",
		"ZANSKAR_PUBLIC_URL": "https://zanskar.example.com", "ZANSKAR_TLS_HOSTS": "zanskar.example.com, 203.0.113.7",
		"ZANSKAR_ISSUER": "Acme O'Brien Ltd", "ZANSKAR_APPS_MAX_SESSIONS": "0", "ZANSKAR_AWS_GATEWAY_PRINCIPAL": "",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("changes:\n got %v\nwant %v", got, want)
	}
	proxy, err := bootedit.Changes(bootedit.Request{TLSMode: "proxy"})
	if err != nil || proxy["ZANSKAR_HTTP_REDIRECT_ADDR"] != "" || proxy["ZANSKAR_LISTEN_ADDR"] != "127.0.0.1:8443" || proxy["ZANSKAR_TRUST_PROXY_TLS"] != "true" {
		t.Fatalf("proxy preset: %v %v", proxy, err)
	}
	for _, k := range []string{"ZANSKAR_PUBLIC_URL", "ZANSKAR_TLS_HOSTS", "ZANSKAR_ISSUER"} {
		if !bootedit.Editable(k) {
			t.Errorf("%s should be editable", k)
		}
	}
	for _, k := range []string{"ZANSKAR_DB_DSN", "ZANSKAR_MASTER_KEY", "ZANSKAR_LISTEN_ADDR", "ZANSKAR_TLS_MODE"} {
		if bootedit.Editable(k) {
			t.Errorf("%s must stay install-only", k)
		}
	}
}

func TestParseRequestIsStrict(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":      "ZANSKAR_DB_DSN=x",
		"unknown field": `{"id":"r1","values":{},"run":"rm -rf /"}`,
		"two values":    `{"id":"r1"}{"id":"r2"}`,
		"too big":       `{"id":"` + strings.Repeat("a", bootedit.MaxRequest) + `"}`,
	} {
		if _, err := bootedit.ParseRequest(strings.NewReader(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	req, err := bootedit.ParseRequest(strings.NewReader(`{"id":"r1","tls_mode":"proxy","values":{"ZANSKAR_LOG_FORMAT":"text"}}`))
	if err != nil || req.ID != "r1" || req.TLSMode != "proxy" || req.Values["ZANSKAR_LOG_FORMAT"] != "text" {
		t.Fatalf("parse: %+v %v", req, err)
	}
}

// TestMergeKeepsEverythingElse: only the changed variables' lines move; the
// master key, comments, blank lines and unknown lines stay byte for byte; a
// repeated variable is written once; "" takes a line out; a new variable is
// added at the end; and the result reads back through the same parser the
// drift banner uses.
func TestMergeKeepsEverythingElse(t *testing.T) {
	// A stand-in for the master key, made here so no key-shaped literal
	// sits in the source.
	key := strings.Repeat("K", 44)
	file := "# Zanskar\n" +
		"ZANSKAR_MASTER_KEY=" + key + "\n" +
		"\n" +
		"ZANSKAR_PUBLIC_URL=https://old.example.com\n" +
		"; a comment\n" +
		"export ZANSKAR_LOG_FORMAT=json\n" +
		"ZANSKAR_HTTP_REDIRECT_ADDR=:80\n" +
		"ZANSKAR_PUBLIC_URL=https://older.example.com\n" +
		"ZANSKAR_ISSUER=Old \\\n" +
		"Name\n" +
		"not a variable line\n" +
		"ZANSKAR_DB_DSN=file:/var/lib/zanskar/zanskar.db"
	changes := map[string]string{
		"ZANSKAR_PUBLIC_URL":         "https://new.example.com",
		"ZANSKAR_LOG_FORMAT":         "text",
		"ZANSKAR_HTTP_REDIRECT_ADDR": "",
		"ZANSKAR_ISSUER":             "Acme Corp",
		"ZANSKAR_TLS_HOSTS":          "gw.example.com",
	}
	got := string(bootedit.Merge([]byte(file), changes))
	want := "# Zanskar\n" +
		"ZANSKAR_MASTER_KEY=" + key + "\n" +
		"\n" +
		"ZANSKAR_PUBLIC_URL=https://new.example.com\n" +
		"; a comment\n" +
		"ZANSKAR_LOG_FORMAT=text\n" +
		"ZANSKAR_ISSUER=\"Acme Corp\"\n" +
		"not a variable line\n" +
		"ZANSKAR_DB_DSN=file:/var/lib/zanskar/zanskar.db\n" +
		"ZANSKAR_TLS_HOSTS=gw.example.com\n"
	if got != want {
		t.Fatalf("merge:\n%s\n---want---\n%s", got, want)
	}
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := lifecycle.ParseEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range changes {
		if parsed[k] != v {
			t.Errorf("%s reads back as %q, want %q", k, parsed[k], v)
		}
	}
	if parsed["ZANSKAR_MASTER_KEY"] != key {
		t.Fatal("the master key line changed")
	}
}
