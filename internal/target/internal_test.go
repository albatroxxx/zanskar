// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type tableResolver map[string][]string

func (f tableResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := f[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	out := make([]net.IPAddr, 0, len(ips))
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

// TestInternal: loopback and the private ranges are internal; public,
// link-local, unspecified and cloud metadata addresses are not.
func TestInternal(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "127.9.9.9", "::1", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "fd00::1", "fc00::1"} {
		if !Internal(net.ParseIP(s)) {
			t.Errorf("%s must be internal", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "203.0.113.9", "169.254.169.254", "0.0.0.0", "100.100.100.200", "2001:db8::1", "fe80::1", "172.32.0.1", "::"} {
		if Internal(net.ParseIP(s)) {
			t.Errorf("%s must not be internal", s)
		}
	}
	if Internal(nil) {
		t.Error("nil must not be internal")
	}
}

// TestInternalDialerRefusesBeforeDialling: a public address is refused by
// the dialer's control hook, so no packet leaves and the refusal is quick;
// a loopback listener is reached as before.
func TestInternalDialerRefusesBeforeDialling(t *testing.T) {
	d := InternalDialer(2 * time.Second)
	started := time.Now()
	_, err := d.DialContext(context.Background(), "tcp", "203.0.113.9:4822")
	if err == nil || !errors.Is(err, ErrAddressForbidden) || !strings.Contains(err.Error(), "not a loopback or private address") {
		t.Fatalf("public address: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("the refusal took %v; it must come before the dial, not from a timeout", time.Since(started))
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("loopback: %v", err)
	}
	_ = conn.Close()
}

// TestCheckInternal: the guacd address check behind the console setting.
func TestCheckInternal(t *testing.T) {
	r := tableResolver{"guacd": {"172.18.0.3"}, "relay.example.com": {"203.0.113.9"}, "mixed": {"10.0.0.5", "203.0.113.9"}, "empty": {}}
	ctx := context.Background()
	for _, ok := range []string{"", "  ", "127.0.0.1:4822", "[::1]:4822", "10.0.0.9:4822", "guacd:4822"} {
		if err := CheckInternal(ctx, r, ok); err != nil {
			t.Errorf("%q: %v, want accepted", ok, err)
		}
	}
	for _, bad := range []string{"8.8.8.8:4822", "[2001:db8::1]:4822", "relay.example.com:4822", "mixed:4822", "nowhere:4822", "empty:4822", "4822", "guacd"} {
		if err := CheckInternal(ctx, r, bad); err == nil || !errors.Is(err, ErrAddressForbidden) {
			t.Errorf("%q: %v, want a refusal", bad, err)
		}
	}
	if err := CheckInternal(ctx, r, "mixed:4822"); err == nil || !strings.Contains(err.Error(), "203.0.113.9") {
		t.Errorf("a name that resolves to a public address must name it: %v", err)
	}
}
