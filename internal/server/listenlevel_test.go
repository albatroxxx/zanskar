// SPDX-License-Identifier: Apache-2.0

package server

import (
	"log/slog"
	"testing"

	"github.com/albatroxxx/zanskar/internal/config"
)

// TestPlainListenerIsAWarningOnlyWhenNoProxyIsDeclared (2026-11-04, live): a
// gateway set up the supported way, in proxy mode with the proxy trusted to
// terminate TLS, wrote a warning at every start and so always showed one in
// the console's log at warn level.
func TestPlainListenerIsAWarningOnlyWhenNoProxyIsDeclared(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  config.Config
		want slog.Level
	}{
		{"proxy mode, proxy trusted", config.Config{TLSMode: config.TLSProxy, TrustProxyTLS: true}, slog.LevelInfo},
		{"proxy mode, proxy not declared", config.Config{TLSMode: config.TLSProxy}, slog.LevelWarn},
		{"no mode, proxy trusted", config.Config{TrustProxyTLS: true}, slog.LevelWarn},
		{"nothing set", config.Config{}, slog.LevelWarn},
	} {
		if got := plainListenerLevel(&c.cfg); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
