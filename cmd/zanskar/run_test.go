// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
)

// TestRunExitCodes: the command line exits 0 on success, 1 on a failed
// command and 2 on bad usage, as scripts and the systemd unit expect.
func TestRunExitCodes(t *testing.T) {
	cases := []struct {
		args []string
		want int
	}{
		{nil, 2},
		{[]string{"no-such-command"}, 2},
		{[]string{"audit"}, 2},
		{[]string{"audit", "nope"}, 2},
		{[]string{"help"}, 0},
		{[]string{"version"}, 0},
		{[]string{"key"}, 1},
		{[]string{"restore"}, 1},
	}
	for _, c := range cases {
		var code int
		_, _, _ = output(t, func() error { code = run(c.args); return nil })
		if code != c.want {
			t.Errorf("zanskar %v: exit %d, want %d", c.args, code, c.want)
		}
	}
}

// TestKeygenAndMigrate: keygen prints a fresh 32-byte key each time, and
// migrate brings an empty database to the current schema, which serve
// then accepts.
func TestKeygenAndMigrate(t *testing.T) {
	keys := map[string]bool{}
	for i := 0; i < 2; i++ {
		out, _, err := output(t, runKeygen)
		key := strings.TrimSpace(out)
		if raw, derr := base64.StdEncoding.DecodeString(key); err != nil || derr != nil || len(raw) != 32 {
			t.Fatalf("keygen printed %q: %v %v", key, err, derr)
		}
		keys[key] = true
	}
	if len(keys) != 2 {
		t.Fatal("keygen printed the same key twice")
	}

	g := newCLIGateway(t, false)
	if code := run([]string{"migrate"}); code != 0 {
		t.Fatalf("migrate exited %d", code)
	}
	g.with(t, func(ctx context.Context, db *store.DB, ring *keyring.Ring) {
		if pending, err := store.Pending(ctx, db); err != nil || len(pending) != 0 {
			t.Fatalf("after migrate: %v pending, %v", pending, err)
		}
		if ring == nil {
			t.Fatal("the key ring must open after migrate")
		}
	})
	if code := run([]string{"migrate"}); code != 0 {
		t.Fatal("migrate must be safe to run twice")
	}
}

// answer feeds lines to promptAnswers on stdin.
func answer(t *testing.T, lines ...string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = saved; _ = r.Close() })
	go func() {
		_, _ = w.WriteString(strings.Join(lines, "\n") + "\n")
		_ = w.Close()
	}()
}

// TestInitPrompts walks the interactive init both ways: Zanskar serving TLS
// with a managed certificate and the names a cloud host needs, and behind a
// TLS proxy, where a public listen address is pulled back to loopback.
// Enter keeps the shown default.
func TestInitPrompts(t *testing.T) {
	t.Run("managed TLS", func(t *testing.T) {
		a := defaultAnswers()
		answer(t,
			"0.0.0.0:443", // listen
			"y",           // terminate TLS in Zanskar
			"y",           // managed certificate
			"zanskar.example.com,203.0.113.9",
			"",       // redirect plain HTTP: keep the default
			"",       // redirect listener: keep the default
			"/srv/z", // data directory
			"y",      // desktops
			"",       // guacd address: default
			"",       // MFA: default (on)
			"Acme", "debug", "text")
		if _, _, err := output(t, func() error { return promptAnswers(&a) }); err != nil {
			t.Fatal(err)
		}
		if a.ListenAddr != "0.0.0.0:443" || a.TLSMode != tlsModeManaged || strings.Join(a.TLSHosts, ",") != "zanskar.example.com,203.0.113.9" ||
			a.RedirectAddr != ":80" || a.DataDir != "/srv/z" || a.GuacdAddr != "127.0.0.1:4822" || !a.RequireMFA ||
			a.Issuer != "Acme" || a.LogLevel != "debug" || a.LogFormat != "text" {
			t.Fatalf("answers: %+v", a)
		}
	})
	t.Run("behind a proxy", func(t *testing.T) {
		a := defaultAnswers()
		answer(t,
			"0.0.0.0:8443", // listen: public, so proxy mode moves it to loopback
			"n",            // TLS is the proxy's job
			"",             // data directory: default
			"n",            // no desktops
			"n",            // no MFA
			"", "", "")
		if _, _, err := output(t, func() error { return promptAnswers(&a) }); err != nil {
			t.Fatal(err)
		}
		if a.TLSMode != tlsModeProxy || a.ListenAddr != "127.0.0.1:8443" || a.RedirectAddr != "" || a.GuacdAddr != "" || a.RequireMFA {
			t.Fatalf("answers: %+v", a)
		}
	})
}
