// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
)

// fakeResolver answers lookups from a table; a name it does not hold does not
// exist. Names under .invalid never resolve for real (RFC 2606), so an answer
// for one can only have come from here.
type fakeResolver map[string][]string

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	answers, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IPAddr, 0, len(answers))
	for _, a := range answers {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

// TestSaveRefusesForbiddenLiterals (L1): an address that is an IP literal the
// gateway must never connect to is refused when a target is created or
// changed, with the probe's 422 address_forbidden, and nothing is stored.
// The refusal is audited. The metadata services outside the link-local range
// are refused by their exact address, so a neighbour is still a target.
func TestSaveRefusesForbiddenLiterals(t *testing.T) {
	e := newEnvWith(t, &Prober{})
	refused := []string{
		"fd00:ec2::254",          // AWS instance metadata over IPv6
		"100.100.100.200",        // Alibaba Cloud metadata
		"169.254.169.254",        // link-local: the metadata service of AWS, Azure, GCP and OCI
		"::ffff:169.254.169.254", // the same, IPv4-mapped
		" 127.0.0.1 ",            // loopback; saved trimmed, so checked trimmed
		"::1",
		"0.0.0.0",
		"ff02::1",
		"224.0.0.251",
	}
	for i, addr := range refused {
		code, out := e.do("POST", "/api/v1/targets", map[string]any{"name": fmt.Sprintf("box-%d", i), "address": addr, "os_family": "linux"}, e.admin)
		if code != 422 || out["code"] != "address_forbidden" {
			t.Errorf("create at %q: %d %v, want 422 address_forbidden", addr, code, out)
		}
	}
	if _, out := e.do("GET", "/api/v1/targets", nil, e.admin); len(out["items"].([]any)) != 0 {
		t.Fatalf("a refused address was stored: %v", out["items"])
	}

	id := e.mkTarget(t, map[string]any{"name": "web", "address": "10.0.0.30", "os_family": "linux"})
	code, out := e.do("PUT", "/api/v1/targets/"+id, map[string]any{"name": "web", "address": "fd00:ec2::254", "os_family": "linux"}, e.admin)
	if code != 422 || out["code"] != "address_forbidden" {
		t.Fatalf("update to the metadata address: %d %v", code, out)
	}
	if _, got := e.do("GET", "/api/v1/targets/"+id, nil, e.admin); got["address"] != "10.0.0.30" {
		t.Fatalf("a refused update was saved: %v", got)
	}

	for i, addr := range []string{"fd00:ec2::253", "100.100.100.201", "10.0.0.31", "web.internal"} {
		if code, out := e.do("POST", "/api/v1/targets", map[string]any{"name": fmt.Sprintf("ok-%d", i), "address": addr, "os_family": "linux"}, e.admin); code != 201 {
			t.Errorf("create at %q: %d %v, want 201", addr, code, out)
		}
	}

	n := 0
	for _, action := range []string{"target.create", "target.update"} {
		for _, ev := range auditActions(t, e, action) {
			var d map[string]any
			_ = json.Unmarshal(ev.Details, &d)
			if ev.Outcome == audit.Failure && d["reason"] == "address_forbidden" {
				n++
			}
		}
	}
	if n != len(refused)+1 {
		t.Fatalf("%d refusals audited, want %d", n, len(refused)+1)
	}
}

// TestSaveRefusesForbiddenDatabaseAddress (L1): a database target is never
// probed, so saving it is the one point before a session at which a
// forbidden literal can be stopped. 169.254.170.2 is the ECS task metadata
// endpoint, which serves the task role's credentials.
func TestSaveRefusesForbiddenDatabaseAddress(t *testing.T) {
	e := newEnv(t)
	for i, addr := range []string{"100.100.100.200", "fd00:ec2::254", "169.254.170.2"} {
		code, out := e.do("POST", "/api/v1/targets", map[string]any{"name": fmt.Sprintf("orders-%d", i), "address": addr, "os_family": "other",
			"engine": "postgres", "tls_mode": "require"}, e.admin)
		if code != 422 || out["code"] != "address_forbidden" {
			t.Errorf("database at %q: %d %v, want 422 address_forbidden", addr, code, out)
		}
	}
	if code, out := e.do("POST", "/api/v1/targets", map[string]any{"name": "orders", "address": "10.0.1.20", "os_family": "other",
		"engine": "postgres", "tls_mode": "require"}, e.admin); code != 201 {
		t.Fatalf("database at a private address: %d %v", code, out)
	}
}

// TestResolveChecksEveryAnswer (L1): a name is looked up once and every answer
// must pass, so one forbidden record among good ones refuses the name, and
// the error says which answer and why. The address returned is the one to
// dial, IPv4 first; a name that does not resolve is a lookup error, not a
// refusal.
func TestResolveChecksEveryAnswer(t *testing.T) {
	ctx := context.Background()
	p := &Prober{Resolver: fakeResolver{
		"mixed.zanskar.invalid": {"10.0.0.7", "169.254.169.254"},
		"meta6.zanskar.invalid": {"fd00:ec2::254"},
		"ok.zanskar.invalid":    {"fd00::7", "10.0.0.7"},
	}}
	for name, want := range map[string]string{
		"mixed.zanskar.invalid": "mixed.zanskar.invalid resolves to 169.254.169.254, which is link-local",
		"meta6.zanskar.invalid": "meta6.zanskar.invalid resolves to fd00:ec2::254, which is a cloud metadata service",
		"100.100.100.200":       "100.100.100.200 is a cloud metadata service",
	} {
		if _, err := p.Resolve(ctx, name); !errors.Is(err, ErrAddressForbidden) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want ErrAddressForbidden saying %q", name, err, want)
		}
	}
	if ip, err := p.Resolve(ctx, "ok.zanskar.invalid"); err != nil || ip.String() != "10.0.0.7" {
		t.Fatalf("ok.zanskar.invalid: %v %v, want 10.0.0.7", ip, err)
	}
	if _, err := p.Resolve(ctx, "gone.zanskar.invalid"); err == nil || errors.Is(err, ErrAddressForbidden) {
		t.Fatalf("a name that does not resolve: %v, want a lookup error", err)
	}
	// A nil Prober applies the rules with no exception.
	var strict *Prober
	if _, err := strict.Resolve(ctx, "127.0.0.1"); !errors.Is(err, ErrAddressForbidden) {
		t.Fatalf("nil prober on loopback: %v", err)
	}
	if err := strict.CheckLiteral("::1"); !errors.Is(err, ErrAddressForbidden) {
		t.Fatalf("nil prober literal check on loopback: %v", err)
	}
}

// TestListenerAddressRefused (L1): when ZANSKAR_LISTEN_ADDR names an address,
// a target there is the gateway itself, and is refused when saved, probed, or
// reached through a name. Only that address: the host's other addresses stay
// allowed, since the documented demo enrols the host's own LAN address.
func TestListenerAddressRefused(t *testing.T) {
	ctx := context.Background()
	e := newEnvWith(t, &Prober{AllowLoopback: true, Self: ListenIP("10.0.0.5:8443"), Resolver: fakeResolver{"gw.zanskar.invalid": {"10.0.0.5"}}})
	for i, addr := range []string{"10.0.0.5", "::ffff:10.0.0.5"} {
		code, out := e.do("POST", "/api/v1/targets", map[string]any{"name": fmt.Sprintf("gw-%d", i), "address": addr, "os_family": "linux"}, e.admin)
		msg, _ := out["message"].(string)
		if code != 422 || out["code"] != "address_forbidden" || !strings.Contains(msg, "the address the gateway listens on") {
			t.Errorf("create at %q: %d %v, want 422 address_forbidden", addr, code, out)
		}
	}
	if code, out := e.do("POST", "/api/v1/targets", map[string]any{"name": "neighbour", "address": "10.0.0.6", "os_family": "linux"}, e.admin); code != 201 {
		t.Fatalf("create at a neighbouring address: %d %v", code, out)
	}
	// A row saved before the rule existed, and a name that resolves to the
	// listener, are refused by the probe.
	for _, addr := range []string{"10.0.0.5", "gw.zanskar.invalid"} {
		tg := &Target{Name: "old-" + addr, Address: addr, OSFamily: Linux}
		if err := NewRepo(e.db).Create(ctx, tg); err != nil {
			t.Fatal(err)
		}
		if code, out := e.do("POST", "/api/v1/targets/"+tg.ID+"/probe", nil, e.admin); code != 422 || out["code"] != "address_forbidden" {
			t.Errorf("probe of %s: %d %v, want 422 address_forbidden", addr, code, out)
		}
	}
}

// TestListenIP: the listener's own address is taken only from a bind to one
// address, never from a wildcard bind or a name.
func TestListenIP(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.5:8443":     "10.0.0.5",
		"[2001:db8::5]:443": "2001:db8::5",
		"127.0.0.1:8443":    "127.0.0.1",
		"0.0.0.0:443":       "",
		"[::]:443":          "",
		":8443":             "",
		"localhost:8443":    "",
		"10.0.0.5":          "",
	} {
		got := ListenIP(in)
		if (want == "" && got != nil) || (want != "" && (got == nil || got.String() != want)) {
			t.Errorf("ListenIP(%q) = %v, want %q", in, got, want)
		}
	}
}
