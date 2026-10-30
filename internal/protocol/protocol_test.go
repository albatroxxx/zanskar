// SPDX-License-Identifier: Apache-2.0

package protocol

import "testing"

// TestName: labels name the protocol as people say it, not as a shouted
// code; the Events page and the command line build their sentences from it.
func TestName(t *testing.T) {
	for in, want := range map[string]string{SSH: "SSH", RDP: "RDP", VNC: "VNC", WinRM: "WinRM", Database: "database"} {
		if got := Name(in); got != want {
			t.Errorf("Name(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestKinds: every protocol but database is either a shell or a desktop,
// never both.
func TestKinds(t *testing.T) {
	for _, p := range []string{SSH, RDP, VNC, WinRM, Database} {
		want := p != Database
		if got := Terminal(p) != Desktop(p); got != want {
			t.Errorf("%s: terminal %v, desktop %v", p, Terminal(p), Desktop(p))
		}
	}
	if !Terminal(SSH) || !Terminal(WinRM) || !Desktop(RDP) || !Desktop(VNC) {
		t.Fatal("ssh and winrm are shells; rdp and vnc are desktops")
	}
}

// TestPolicyKinds (ADR 0036): each kind serves its own protocols and nothing else,
// so a grant can never offer ssh on a database.
func TestPolicyKinds(t *testing.T) {
	for _, k := range Kinds {
		if !ValidKind(k) || len(KindProtocols(k)) == 0 {
			t.Fatalf("kind %q has no protocols", k)
		}
	}
	if ValidKind("vm") || len(KindProtocols("vm")) != 0 {
		t.Fatal("an unknown kind is valid")
	}
	cases := []struct {
		kind, proto string
		want        bool
	}{
		{KindHost, SSH, true}, {KindHost, WinRM, true}, {KindHost, Database, false}, {KindHost, HTTP, false},
		{KindAutoscaling, RDP, true}, {KindAutoscaling, HTTP, false},
		{KindDatabase, Database, true}, {KindDatabase, SSH, false},
		{KindApplication, HTTP, true}, {KindApplication, VNC, false},
	}
	for _, c := range cases {
		if got := KindServes(c.kind, c.proto); got != c.want {
			t.Errorf("KindServes(%s, %s) = %v", c.kind, c.proto, got)
		}
	}
	// A copy: the caller cannot change what a kind serves.
	p := KindProtocols(KindHost)
	p[0] = "x"
	if KindProtocols(KindHost)[0] != SSH {
		t.Fatal("KindProtocols handed out its own slice")
	}
}
