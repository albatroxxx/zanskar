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
		{"proxy mode with public bind is rejected", func(a *initAnswers) { a.TLSMode = tlsModeProxy; a.RedirectAddr = ""; a.ListenAddr = "0.0.0.0:8443" }, false},
		{"managed mode on 443 with the redirect (the default)", func(*initAnswers) {}, true},
		{"redirect in proxy mode is rejected", func(a *initAnswers) {
			a.TLSMode = tlsModeProxy
			a.ListenAddr = "127.0.0.1:8443"
			a.RedirectAddr = ":80"
		}, false},
		{"redirect equal to the listen address is rejected", func(a *initAnswers) { a.RedirectAddr = "0.0.0.0:443" }, false},
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
	a.TLSMode, a.ListenAddr, a.RedirectAddr = tlsModeProxy, "127.0.0.1:8443", ""
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

func TestGuacdRunHint(t *testing.T) {
	lines := guacdRunHint("127.0.0.1:4822")
	if len(lines) != 2 || !strings.Contains(lines[0], "-p 127.0.0.1:4822:4822") || !strings.Contains(lines[1], "guacamole/guacd:1.6.0") {
		t.Fatalf("loopback hint: %q", lines)
	}
	if lines := guacdRunHint("localhost:5000"); !strings.Contains(lines[0], "-p 127.0.0.1:5000:4822") {
		t.Fatalf("custom loopback port: %q", lines)
	}
	lines = guacdRunHint("10.0.0.9:4822")
	if len(lines) != 3 || !strings.Contains(lines[0], "10.0.0.9") || !strings.Contains(lines[1], "-p 4822:4822") {
		t.Fatalf("remote host hint: %q", lines)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "HOME=/tmp") {
		t.Fatalf("HOME must be set for the image's user: %q", lines)
	}
}

// TestRenderEnvManagedMode: managed TLS writes the mode and no certificate
// files, and a public bind is accepted for it.
func TestRenderEnvManagedMode(t *testing.T) {
	a := validAnswers()
	a.TLSMode = tlsModeManaged
	a.ListenAddr = "0.0.0.0:443"
	if err := validateAnswers(a); err != nil {
		t.Fatal(err)
	}
	out := renderEnv(a)
	for _, want := range []string{"ZANSKAR_TLS_MODE=managed\n", "ZANSKAR_LISTEN_ADDR=0.0.0.0:443\n", "ZANSKAR_HTTP_REDIRECT_ADDR=:80\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("managed env missing %q: %s", want, out)
		}
	}
	if d := defaultAnswers(); d.TLSMode != tlsModeManaged || d.ListenAddr != "0.0.0.0:443" || d.RedirectAddr != ":80" {
		t.Fatalf("defaults: %+v", d)
	}
	for _, no := range []string{"ZANSKAR_TLS_CERT", "ZANSKAR_TLS_KEY", "ZANSKAR_TRUST_PROXY_TLS"} {
		if strings.Contains(out, no) {
			t.Errorf("managed env must not set %s", no)
		}
	}
}

// TestInitWritesCertificateNames covers the cloud case: the public address is
// translated upstream, so the machine cannot find it and it has to be named.
// Without it the certificate omits the address people use, which shows up as a
// name-mismatch warning and a plain-HTTP listener that refuses to redirect.
func TestInitWritesCertificateNames(t *testing.T) {
	a := defaultAnswers()
	a.TLSHosts = []string{"zanskar.example.com", "203.0.113.9"}
	a.MasterKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if err := validateAnswers(a); err != nil {
		t.Fatalf("names must be accepted: %v", err)
	}
	got := renderEnv(a)
	if !strings.Contains(got, "ZANSKAR_TLS_HOSTS=zanskar.example.com,203.0.113.9") {
		t.Fatalf("env file does not carry the names:\n%s", got)
	}

	// A name that is neither a host name nor an address is refused.
	bad := a
	bad.TLSHosts = []string{"https://zanskar.example.com/"}
	if err := validateAnswers(bad); err == nil {
		t.Fatal("a URL is not a certificate name")
	}

	// They belong to a certificate Zanskar serves, not to a proxy in front.
	proxied := a
	proxied.TLSMode, proxied.ListenAddr, proxied.RedirectAddr = tlsModeProxy, "127.0.0.1:8443", ""
	if err := validateAnswers(proxied); err == nil {
		t.Fatal("certificate names make no sense in behind-proxy mode")
	}

	// Nothing is written when nothing is named.
	none := defaultAnswers()
	none.MasterKey = a.MasterKey
	if strings.Contains(renderEnv(none), "ZANSKAR_TLS_HOSTS") {
		t.Fatal("the variable must be absent when no name is given")
	}
}
