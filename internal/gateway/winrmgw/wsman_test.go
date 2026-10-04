// SPDX-License-Identifier: Apache-2.0

package winrmgw

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/gateway/winrmgw/winrmtest"
)

func endpointFor(t *testing.T, f *winrmtest.Server, pin string) Endpoint {
	t.Helper()
	host, port := f.Address(t)
	if pin == "" {
		pin = f.Fingerprint()
	}
	return Endpoint{Address: host, Port: port, UseTLS: true, PinnedFingerprint: pin}
}

// TestDialAndRunThroughThePin drives the real WinRM client against the
// stand-in listener: a pinned dial verifies the credential, and each line
// runs as its own PowerShell command with its output and exit code returned.
func TestDialAndRunThroughThePin(t *testing.T) {
	f := winrmtest.New(t)
	ctx := context.Background()
	c, err := Dial(ctx, endpointFor(t, f, ""), Auth{Username: "admin", Password: "pw-1"}, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sh, err := c.Shell(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sh.Close() }()
	var out bytes.Buffer
	code, err := sh.Run(ctx, "Get-Service winrm", &out, io.Discard)
	if err != nil || code != 0 || !strings.Contains(out.String(), "ran: Get-Service winrm") {
		t.Fatalf("run: %d %v %q", code, err, out.String())
	}
	if code, err := sh.Run(ctx, "exit 3", io.Discard, io.Discard); err != nil || code != 3 {
		t.Fatalf("exit code: %d %v, want 3", code, err)
	}
}

// TestDialRefusals: a wrong password is an authentication failure; a
// credential that authenticates but may not open a shell is reported as
// such (the local-administrator rule); and a listener presenting a
// certificate other than the pinned one never receives a request, so the
// credential is never sent to it.
func TestDialRefusals(t *testing.T) {
	f := winrmtest.New(t)
	ctx := context.Background()

	_, err := Dial(ctx, endpointFor(t, f, ""), Auth{Username: "admin", Password: "wrong"}, 5*time.Second)
	if !errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("wrong password: %v, want ErrAuthFailed", err)
	}
	_, err = Dial(ctx, endpointFor(t, f, ""), Auth{Username: "limited", Password: "pw-1"}, 5*time.Second)
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("not an administrator: %v, want ErrNotAuthorized", err)
	}

	before := f.Requests.Load()
	_, err = Dial(ctx, endpointFor(t, f, strings.Repeat("ab", 32)), Auth{Username: "admin", Password: "pw-1"}, 5*time.Second)
	if !errors.Is(err, ErrCertMismatch) {
		t.Fatalf("wrong pin: %v, want ErrCertMismatch", err)
	}
	if f.Requests.Load() != before {
		t.Fatal("a listener with the wrong certificate received a request carrying the credential")
	}
	if _, err := Dial(ctx, Endpoint{Address: "127.0.0.1", Port: 1, UseTLS: true}, Auth{Username: "admin", Password: "pw-1"}, time.Second); !errors.Is(err, ErrUnpinned) {
		t.Fatalf("TLS with neither a pin nor a CA: %v, want ErrUnpinned", err)
	}
}
