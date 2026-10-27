// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/target"
)

// fakeResolver answers a hostname lookup from a table, so no test reaches DNS.
type fakeResolver map[string][]string

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
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

// TestCredentialRoutingSettingsAskForAStepUp: the guacd address and the
// relay image decide where a vaulted credential is sent, so setting or
// resetting them from the console needs an authenticator code proved in the
// last five minutes; a session without one is refused with
// step_up_required, and the other settings are not affected (threat model
// risk 7, decided 2026-10-27).
func TestCredentialRoutingSettingsAskForAStepUp(t *testing.T) {
	e := newEnv(t)
	for _, key := range []string{KeyGuacdAddr, KeyDBProxyImage} {
		if code, out := e.do("PUT", "/api/v1/admin/settings/"+key, map[string]string{"value": "x"}, e.admin, e.aCSRF); code != 403 || out["code"] != "step_up_required" {
			t.Fatalf("set %s without a recent code: %d %v", key, code, out)
		}
		if code, out := e.do("DELETE", "/api/v1/admin/settings/"+key, nil, e.admin, e.aCSRF); code != 403 || out["code"] != "step_up_required" {
			t.Fatalf("reset %s without a recent code: %d %v", key, code, out)
		}
	}
	if code, out := e.do("PUT", "/api/v1/admin/settings/"+KeyLogLevel, map[string]string{"value": "debug"}, e.admin, e.aCSRF); code != 200 {
		t.Fatalf("a setting that routes no credential must not ask for a code: %d %v", code, out)
	}
	if evs, _, err := e.audit.List(context.Background(), audit.Filter{ObjectType: "setting", ObjectID: KeyGuacdAddr}); err != nil || len(evs) != 0 {
		t.Fatalf("a refused change was audited as an update: %v %v", evs, err)
	}

	e.proved(t)
	if code, out := e.do("PUT", "/api/v1/admin/settings/"+KeyGuacdAddr, map[string]string{"value": "127.0.0.1:4822"}, e.admin, e.aCSRF); code != 200 || out["value"] != "127.0.0.1:4822" {
		t.Fatalf("set guacd with a recent code: %d %v", code, out)
	}
	if code, out := e.do("DELETE", "/api/v1/admin/settings/"+KeyGuacdAddr, nil, e.admin, e.aCSRF); code != 200 {
		t.Fatalf("reset guacd with a recent code: %d %v", code, out)
	}
	if v, _ := e.svc.Get(KeyGuacdAddr); v.Source == SourceConsole {
		t.Fatalf("reset left a console value: %+v", v)
	}
	// The listing says which settings ask for a code, so the console can.
	var stepUp []string
	for _, v := range e.svc.All() {
		if v.StepUp {
			stepUp = append(stepUp, v.Key)
		}
	}
	if strings.Join(stepUp, ",") != KeyGuacdAddr+","+KeyDBProxyImage {
		t.Fatalf("settings marked step_up: %v", stepUp)
	}
}

// TestGuacdAddressIsBoundedFromTheConsole: with the gateway's check in
// place (main.go registers it), the console may name guacd only by a
// loopback or private address, or by a name that resolves to one; a public
// address, a public name or a name that does not resolve is refused with
// the reason. Empty, which turns desktops off, passes.
func TestGuacdAddressIsBoundedFromTheConsole(t *testing.T) {
	e := newEnv(t)
	e.proved(t)
	r := fakeResolver{"guacd": {"172.18.0.3"}, "relay.example.com": {"203.0.113.9"}, "mixed": {"10.0.0.5", "203.0.113.9"}}
	e.svc.Check(KeyGuacdAddr, func(v string) error { return target.CheckInternal(context.Background(), r, v) })
	for _, ok := range []string{"127.0.0.1:4822", "10.1.2.3:4822", "192.168.0.9:4822", "172.16.5.5:4822", "[::1]:4822", "[fd00::9]:4822", "guacd:4822", ""} {
		if code, out := e.do("PUT", "/api/v1/admin/settings/"+KeyGuacdAddr, map[string]string{"value": ok}, e.admin, e.aCSRF); code != 200 {
			t.Fatalf("%q must be accepted: %d %v", ok, code, out)
		}
	}
	for _, bad := range []string{"8.8.8.8:4822", "203.0.113.9:4822", "[2001:db8::1]:4822", "169.254.169.254:80", "0.0.0.0:4822", "relay.example.com:4822", "mixed:4822", "nowhere:4822"} {
		code, out := e.do("PUT", "/api/v1/admin/settings/"+KeyGuacdAddr, map[string]string{"value": bad}, e.admin, e.aCSRF)
		if msg, _ := out["message"].(string); code != 400 || !strings.Contains(msg, "private") && !strings.Contains(msg, "resolve") {
			t.Fatalf("%q must be refused with the reason: %d %v", bad, code, out)
		}
	}
	if v, _ := e.svc.Get(KeyGuacdAddr); v.Value != "" {
		t.Fatalf("a refused address was stored: %+v", v)
	}
}

// TestRelayImageMustBePinnedFromTheConsole: the console accepts the relay
// image only with a digest; a tag alone is refused, and says so. The
// environment file keeps naming a tag (the default does).
func TestRelayImageMustBePinnedFromTheConsole(t *testing.T) {
	e := newEnv(t)
	e.proved(t)
	e.svc.Check(KeyDBProxyImage, RequireDigest)
	digest := "@sha256:" + strings.Repeat("ab", 32)
	for _, ok := range []string{"ghcr.io/albatroxxx/zanskar" + digest, "registry.example.com/zanskar:1.5.0" + digest} {
		if code, out := e.do("PUT", "/api/v1/admin/settings/"+KeyDBProxyImage, map[string]string{"value": ok}, e.admin, e.aCSRF); code != 200 {
			t.Fatalf("%q must be accepted: %d %v", ok, code, out)
		}
	}
	for _, bad := range []string{"ghcr.io/albatroxxx/zanskar:1.5.0", "zanskar:local", "registry.example.com/zanskar"} {
		code, out := e.do("PUT", "/api/v1/admin/settings/"+KeyDBProxyImage, map[string]string{"value": bad}, e.admin, e.aCSRF)
		if msg, _ := out["message"].(string); code != 400 || !strings.Contains(msg, "digest") {
			t.Fatalf("%q must be refused for lacking a digest: %d %v", bad, code, out)
		}
	}
	if err := RequireDigest(DefaultDBProxyImage()); err == nil {
		t.Fatal("the default names a tag; the check must be a console-only rule, so this must fail on it")
	}
	if _, err := Validate(Definition{Key: KeyDBProxyImage, Type: TypeString}, DefaultDBProxyImage()); err != nil {
		t.Fatalf("the default must still validate for the environment: %v", err)
	}
}
