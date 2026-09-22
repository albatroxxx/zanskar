// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validAnswers() initAnswers {
	a := defaultAnswers()
	a.MasterKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 bytes base64
	return a
}

func TestValidateAnswers(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*initAnswers)
		ok   bool
	}{
		{"default proxy is valid", func(*initAnswers) {}, true},
		{"cert mode with both files", func(a *initAnswers) { a.TLSMode = tlsModeCert; a.TLSCert = "/c"; a.TLSKey = "/k" }, true},
		{"cert mode missing key", func(a *initAnswers) { a.TLSMode = tlsModeCert; a.TLSCert = "/c" }, false},
		{"proxy mode with public bind is rejected", func(a *initAnswers) { a.ListenAddr = "0.0.0.0:8443" }, false},
		{"cert mode allows public bind", func(a *initAnswers) {
			a.TLSMode = tlsModeCert
			a.TLSCert = "/c"
			a.TLSKey = "/k"
			a.ListenAddr = "0.0.0.0:8443"
		}, true},
		{"listen without port", func(a *initAnswers) { a.ListenAddr = "127.0.0.1" }, false},
		{"relative data dir", func(a *initAnswers) { a.DataDir = "data" }, false},
		{"bad log level", func(a *initAnswers) { a.LogLevel = "trace" }, false},
		{"bad log format", func(a *initAnswers) { a.LogFormat = "yaml" }, false},
		{"empty master key", func(a *initAnswers) { a.MasterKey = "" }, false},
		{"non-base64 master key", func(a *initAnswers) { a.MasterKey = "not base64!!!" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := validAnswers()
			tc.mut(&a)
			err := validateAnswers(a)
			if tc.ok && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestRenderEnvProxyMode(t *testing.T) {
	a := validAnswers()
	a.GuacdAddr = "127.0.0.1:4822"
	out := renderEnv(a)
	for _, want := range []string{
		"ZANSKAR_LISTEN_ADDR=127.0.0.1:8443",
		"ZANSKAR_TRUST_PROXY_TLS=true",
		"ZANSKAR_TRUSTED_PROXIES=127.0.0.1/32,::1/128",
		"ZANSKAR_GUACD_ADDR=127.0.0.1:4822",
		"ZANSKAR_REQUIRE_MFA=true",
		"ZANSKAR_MASTER_KEY=" + a.MasterKey,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("proxy env missing %q", want)
		}
	}
	if strings.Contains(out, "ZANSKAR_TLS_CERT") {
		t.Error("proxy env must not set a TLS certificate")
	}
	// The DSN must be quoted so a shell sourcing the file does not choke on the
	// & and () in the pragmas.
	if !strings.Contains(out, `ZANSKAR_DB_DSN="file:`) {
		t.Error("DB_DSN must be double-quoted")
	}
}

func TestRenderEnvCertMode(t *testing.T) {
	a := validAnswers()
	a.TLSMode = tlsModeCert
	a.TLSCert, a.TLSKey = "/etc/tls/z.crt", "/etc/tls/z.key"
	a.GuacdAddr = ""
	out := renderEnv(a)
	for _, want := range []string{"ZANSKAR_TLS_CERT=/etc/tls/z.crt", "ZANSKAR_TLS_KEY=/etc/tls/z.key"} {
		if !strings.Contains(out, want) {
			t.Errorf("cert env missing %q", want)
		}
	}
	if strings.Contains(out, "ZANSKAR_TRUST_PROXY_TLS") {
		t.Error("cert env must not set TRUST_PROXY_TLS")
	}
	if strings.Contains(out, "ZANSKAR_GUACD_ADDR=") {
		t.Error("desktop disabled: GUACD_ADDR must not be set")
	}
}

func TestMasterKeyFrom(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "env")
	if err := os.WriteFile(f, []byte("# c\nZANSKAR_LISTEN_ADDR=x\nZANSKAR_MASTER_KEY=deadbeef==\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := masterKeyFrom(f); got != "deadbeef==" {
		t.Fatalf("masterKeyFrom = %q, want deadbeef==", got)
	}
	if got := masterKeyFrom(filepath.Join(dir, "nope")); got != "" {
		t.Fatalf("missing file must yield empty, got %q", got)
	}
	noKey := filepath.Join(dir, "nokey")
	_ = os.WriteFile(noKey, []byte("ZANSKAR_LISTEN_ADDR=x\n"), 0o600)
	if got := masterKeyFrom(noKey); got != "" {
		t.Fatalf("no key line must yield empty, got %q", got)
	}
}

func TestWriteFileAtomicMode(t *testing.T) {
	f := filepath.Join(t.TempDir(), "sub", "env")
	if err := writeFileAtomic(f, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	b, _ := os.ReadFile(f)
	if string(b) != "data" {
		t.Fatalf("content = %q", b)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8443", true},
		{"localhost:8443", true},
		{"[::1]:8443", true},
		{"0.0.0.0:8443", false},
		{"10.0.0.5:8443", false},
		{"garbage", false},
	} {
		if got := isLoopbackAddr(tc.addr); got != tc.want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}
