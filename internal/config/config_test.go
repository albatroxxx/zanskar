// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("ZANSKAR_MASTER_KEY", "")
	c, err := Load(Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.DBDriver != DriverSQLite || c.ListenAddr != "127.0.0.1:8443" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestLoadRequiresMasterKeyForServe(t *testing.T) {
	t.Setenv("ZANSKAR_MASTER_KEY", "")
	if _, err := Load(Options{RequireMasterKey: true}); err == nil || !strings.Contains(err.Error(), "ZANSKAR_MASTER_KEY") {
		t.Fatalf("expected master key error, got %v", err)
	}
}

func TestLoadRejectsPlainHTTPOffLoopback(t *testing.T) {
	t.Setenv("ZANSKAR_LISTEN_ADDR", "0.0.0.0:8443")
	if _, err := Load(Options{}); err == nil || !strings.Contains(err.Error(), "plain HTTP") {
		t.Fatalf("expected plain HTTP refusal, got %v", err)
	}
}

func TestLoadMasterKeyLength(t *testing.T) {
	t.Setenv("ZANSKAR_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 16)))
	if _, err := Load(Options{}); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("expected length error, got %v", err)
	}
	t.Setenv("ZANSKAR_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	c, err := Load(Options{RequireMasterKey: true})
	if err != nil || len(c.MasterKey) != 32 {
		t.Fatalf("expected valid key, got %v", err)
	}
}

// TestTLSModeDerivation: unset, the mode follows the certificate variables
// so existing installs keep their behaviour; managed allows a public bind
// with no files; file without files is refused.
func TestTLSModeDerivation(t *testing.T) {
	base := map[string]string{"ZANSKAR_MASTER_KEY": base64.StdEncoding.EncodeToString(make([]byte, 32))}
	cases := []struct {
		env  map[string]string
		mode string
		ok   bool
	}{
		{map[string]string{}, TLSProxy, true},
		{map[string]string{"ZANSKAR_TLS_CERT": "c.pem", "ZANSKAR_TLS_KEY": "k.pem"}, TLSFile, true},
		{map[string]string{"ZANSKAR_TLS_MODE": "managed", "ZANSKAR_LISTEN_ADDR": "0.0.0.0:443"}, TLSManaged, true},
		{map[string]string{"ZANSKAR_TLS_MODE": "file"}, TLSFile, false},
		{map[string]string{"ZANSKAR_TLS_MODE": "sideways"}, "", false},
	}
	for _, c := range cases {
		for k, v := range base {
			t.Setenv(k, v)
		}
		for _, k := range []string{"ZANSKAR_TLS_CERT", "ZANSKAR_TLS_KEY", "ZANSKAR_TLS_MODE", "ZANSKAR_LISTEN_ADDR"} {
			t.Setenv(k, "")
		}
		for k, v := range c.env {
			t.Setenv(k, v)
		}
		cfg, err := Load(Options{RequireMasterKey: true})
		if (err == nil) != c.ok {
			t.Fatalf("%v: err=%v", c.env, err)
		}
		if err == nil && (cfg.TLSMode != c.mode || cfg.ServesTLS() != (c.mode != TLSProxy) || cfg.SecureCookies() != (c.mode != TLSProxy)) {
			t.Fatalf("%v: mode %q serves=%v secure=%v", c.env, cfg.TLSMode, cfg.ServesTLS(), cfg.SecureCookies())
		}
	}
}

// writeKey writes a master key file with the given mode.
func writeKey(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // WriteFile's mode is filtered by the umask
		t.Fatal(err)
	}
	return p
}

func TestLoadMasterKeyFile(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes32())
	t.Setenv("ZANSKAR_MASTER_KEY", "")
	t.Setenv("ZANSKAR_MASTER_KEY_FILE", writeKey(t, key+"\n", 0o400))
	c, err := Load(Options{RequireMasterKey: true})
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	if base64.StdEncoding.EncodeToString(c.MasterKey) != key || c.MasterKeyFile == "" {
		t.Fatalf("key not loaded from the file: %+v", c.MasterKeyFile)
	}
}

func TestLoadMasterKeyFileRefusals(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes32())
	cases := []struct {
		name, env, content, want string
		mode                     os.FileMode
	}{
		{"readable by group", "", key, "only its owner may read it", 0o440},
		{"readable by others", "", key, "only its owner may read it", 0o404},
		{"both set", key, key, "not both", 0o400},
		{"empty", "", "\n", "is empty", 0o600},
		{"short", "", base64.StdEncoding.EncodeToString(make([]byte, 16)), "32 bytes", 0o600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ZANSKAR_MASTER_KEY", tc.env)
			t.Setenv("ZANSKAR_MASTER_KEY_FILE", writeKey(t, tc.content, tc.mode))
			_, err := Load(Options{RequireMasterKey: true})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
			if strings.Contains(err.Error(), "is required") {
				t.Fatalf("a named key file's own error must be the only one: %v", err)
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		t.Setenv("ZANSKAR_MASTER_KEY", "")
		t.Setenv("ZANSKAR_MASTER_KEY_FILE", filepath.Join(t.TempDir(), "nope"))
		if _, err := Load(Options{RequireMasterKey: true}); err == nil || !strings.Contains(err.Error(), "ZANSKAR_MASTER_KEY_FILE") {
			t.Fatalf("want a key-file error, got %v", err)
		}
	})
}

func bytes32() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}
