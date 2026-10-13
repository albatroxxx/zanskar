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
