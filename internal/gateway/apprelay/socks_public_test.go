// SPDX-License-Identifier: Apache-2.0

package apprelay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"
	"testing"
)

type resolverFunc func(ctx context.Context, host string) ([]net.IPAddr, error)

func (f resolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

// publicRelay serves a relay routing app.corp:443 to an echo backend, with
// Public as given, lookups answered from a table, and every dial recorded
// and sent to the backend whatever address was asked for.
func publicRelay(t *testing.T, public bool) (addr string, dialled func() []string) {
	t.Helper()
	be := echoBackend(t).Addr().String()
	port := freePort(t)
	lookups := map[string][]string{
		"cdn.example":   {"93.184.216.34"},
		"both.example":  {"2606:4700:4700::1111", "93.184.216.34"},
		"v6.example":    {"2606:4700:4700::1111"},
		"intra.example": {"10.0.0.7"},
		"mixed.example": {"93.184.216.34", "169.254.169.254"},
		"empty.example": {},
	}
	var mu sync.Mutex
	var dials []string
	r := &Relay{
		Config:     Config{SOCKS: &SOCKS{Listen: "internal:" + strconv.Itoa(port), Allow: []Route{{Host: "app.corp", Port: 443, To: be}}, Public: public}},
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		InternalIP: "127.0.0.1",
		Resolver: resolverFunc(func(_ context.Context, host string) ([]net.IPAddr, error) {
			ips, ok := lookups[host]
			if !ok {
				return nil, errors.New("no such host")
			}
			var out []net.IPAddr
			for _, ip := range ips {
				out = append(out, net.IPAddr{IP: net.ParseIP(ip)})
			}
			return out, nil
		}),
		Dial: func(ctx context.Context, to string) (net.Conn, error) {
			mu.Lock()
			dials = append(dials, to)
			mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, "tcp", be)
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = r.Serve(ctx) }()
	addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	waitListening(t, addr)
	return addr, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(dials)
	}
}

// TestSOCKSPublicDependencies (2026-11-03): under Public an unlisted host
// goes through on 80 or 443 when every address it resolves to is public,
// dialled at the address checked (IPv4 first), and a route stays pinned.
// What resolves anywhere private, link-local or to a metadata service, an
// address of that kind written out, another port, the browser's own
// service hosts, and a name that does not resolve are refused before
// anything is dialled.
func TestSOCKSPublicDependencies(t *testing.T) {
	addr, dialled := publicRelay(t, true)
	through := []struct {
		host string
		port int
		to   string
	}{
		{"cdn.example", 443, "93.184.216.34:443"},
		{"CDN.example.", 80, "93.184.216.34:80"},
		{"both.example", 443, "93.184.216.34:443"},
		{"v6.example", 443, "[2606:4700:4700::1111]:443"},
		{"93.184.216.34", 443, "93.184.216.34:443"},
		{"app.corp", 443, ""},
	}
	var want []string
	for _, c := range through {
		code, conn := socksClient(t, addr, []byte{0}, socksConnect, atypDomain, c.host, c.port)
		if code != replySucceeded {
			t.Fatalf("%s:%d: reply %d, want success", c.host, c.port, code)
		}
		echoes(t, conn, "through "+c.host)
		if c.to != "" {
			want = append(want, c.to)
		} else {
			want = append(want, dialled()[len(dialled())-1]) // the route's own pinned address
		}
	}
	if got := dialled(); !slices.Equal(got, want) {
		t.Errorf("dialled %v, want %v", got, want)
	}
	refused := []struct {
		host string
		port int
	}{
		{"intra.example", 443}, {"mixed.example", 443}, {"empty.example", 443}, {"gone.example", 443},
		{"cdn.example", 8443}, {"cdn.example", 22}, {"93.184.216.34", 8080},
		{"10.0.0.7", 80}, {"169.254.169.254", 80}, {"127.0.0.1", 80}, {"100.100.100.200", 80}, {"fd00:ec2::254", 80}, {"0.0.0.0", 80},
		{"accounts.google.com", 443}, {"update.googleapis.com", 80}, {"clients2.google.com", 443},
	}
	before := len(dialled())
	for _, c := range refused {
		if code, _ := socksClient(t, addr, []byte{0}, socksConnect, atypDomain, c.host, c.port); code != replyNotAllowed {
			t.Errorf("%s:%d: reply %d, want %d (not allowed)", c.host, c.port, code, replyNotAllowed)
		}
	}
	if n := len(dialled()); n != before {
		t.Errorf("a refused destination was dialled: %v", dialled()[before:])
	}
}

// TestSOCKSWithoutPublicIsUnchanged: with Public off, a public host that
// would go through is refused as before, and nothing is looked up or
// dialled for it.
func TestSOCKSWithoutPublicIsUnchanged(t *testing.T) {
	addr, dialled := publicRelay(t, false)
	for _, host := range []string{"cdn.example", "93.184.216.34"} {
		if code, _ := socksClient(t, addr, []byte{0}, socksConnect, atypDomain, host, 443); code != replyNotAllowed {
			t.Errorf("%s: reply %d, want %d (not allowed)", host, code, replyNotAllowed)
		}
	}
	if got := dialled(); len(got) != 0 {
		t.Errorf("dialled %v", got)
	}
}
