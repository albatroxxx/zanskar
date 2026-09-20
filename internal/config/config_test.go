// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/base64"
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
