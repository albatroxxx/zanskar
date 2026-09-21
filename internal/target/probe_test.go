// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startSSHServer runs a minimal SSH server that completes key exchange and
// rejects every authentication. Returns its port and host key fingerprint.
func startSSHServer(t *testing.T) (int, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, errors.New("no") },
		ServerVersion:    "SSH-2.0-ZanskarTest_1.0",
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _, _, _ = ssh.NewServerConn(c, cfg)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ssh.FingerprintSHA256(signer.PublicKey())
}

func TestProbeSSHCapturesHostKey(t *testing.T) {
	port, want := startSSHServer(t)
	p := &Prober{AllowLoopback: true}
	res, err := p.Probe(context.Background(), "127.0.0.1", map[Protocol]int{SSH: port}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reachable[SSH] || res.SSHHostKey == nil {
		t.Fatalf("ssh not captured: %+v errors=%v", res, res.Errors)
	}
	if res.SSHHostKey.Fingerprint != want || res.SSHHostKey.Type != "ssh-ed25519" || res.SSHHostKey.Banner != "SSH-2.0-ZanskarTest_1.0" {
		t.Fatalf("unexpected host key: %+v (want %s)", res.SSHHostKey, want)
	}
	if len(res.Capabilities) != 1 || res.Capabilities[0] != SSH {
		t.Fatalf("capabilities: %v", res.Capabilities)
	}
	if res.Ports[SSH].Error != "" {
		t.Fatalf("unexpected error recorded: %s", res.Ports[SSH].Error)
	}
}

func TestProbeTLSCapturesCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	sum := sha256.Sum256(srv.Certificate().Raw)
	want := hex.EncodeToString(sum[:])

	p := &Prober{AllowLoopback: true}
	res, err := p.Probe(context.Background(), "127.0.0.1", map[Protocol]int{WinRM: port, SSH: 1}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reachable[WinRM] || res.WinRMTLS == nil || res.WinRMTLS.Fingerprint != want || res.WinRMTLS.Source != "winrm" {
		t.Fatalf("tls not captured: %+v errors=%v", res.WinRMTLS, res.Errors)
	}
	if res.Reachable[SSH] || res.Ports[SSH].Error == "" {
		t.Fatalf("port 1 should be unreachable with an error: %+v", res.Ports[SSH])
	}
	if len(res.Capabilities) != 1 || res.Capabilities[0] != WinRM {
		t.Fatalf("capabilities: %v", res.Capabilities)
	}
}

func TestProbeVNCBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("RFB 003.008\n"))
			_ = c.Close()
		}
	}()
	p := &Prober{AllowLoopback: true}
	res, err := p.Probe(context.Background(), "127.0.0.1", map[Protocol]int{VNC: ln.Addr().(*net.TCPAddr).Port}, 2*time.Second)
	if err != nil || res.VNCVersion != "RFB 003.008" {
		t.Fatalf("vnc: %q %v", res.VNCVersion, err)
	}
}

func TestProbeRefusesForbiddenAddresses(t *testing.T) {
	p := &Prober{}
	for _, addr := range []string{"127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "fe80::1"} {
		if _, err := p.Probe(context.Background(), addr, map[Protocol]int{SSH: 22}, time.Second); !errors.Is(err, ErrAddressForbidden) {
			t.Errorf("%s: expected ErrAddressForbidden, got %v", addr, err)
		}
	}
	// Private ranges are fine (connection will simply fail fast or time out).
	res, err := p.Probe(context.Background(), "192.0.2.1", map[Protocol]int{SSH: 22}, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("documentation range should be allowed: %v", err)
	}
	if res.Reachable[SSH] {
		t.Fatal("192.0.2.1 must not be reachable")
	}
}
