// SPDX-License-Identifier: Apache-2.0

package target

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/credential"
)

// certServer is an SSH server that accepts user certificates signed by any
// authority in trusted, the way sshd reads TrustedUserCAKeys; the set can
// change while it runs, as an operator would edit the file mid-rotation.
type certServer struct {
	mu      sync.Mutex
	trusted []ssh.PublicKey
	port    int
	fp      string
}

func (s *certServer) trust(authorizedKey string) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	s.trusted = append(s.trusted, pub)
	s.mu.Unlock()
}

func startCertServer(t *testing.T) *certServer {
	t.Helper()
	s := &certServer{}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	checker := &ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, ca := range s.trusted {
			if bytes.Equal(k.Marshal(), ca.Marshal()) {
				return true
			}
		}
		return false
	}}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: checker.Authenticate,
		PasswordCallback:  func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, errors.New("no") },
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
				conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "probe only")
				}
				_ = conn.Close()
			}()
		}
	}()
	s.port, s.fp = ln.Addr().(*net.TCPAddr).Port, ssh.FingerprintSHA256(signer.PublicKey())
	return s
}

// TestProbeCertificate: the certificate probe is a real login with a minted
// certificate, refused until the host key is trusted and the SSH slot holds
// an authority, distinguishes "the target does not trust this key" from
// success, and checks the prepared key during a rotation (ADR 0022).
func TestProbeCertificate(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	srv := startCertServer(t)

	code, body := e.do("POST", "/api/v1/targets", map[string]any{"name": "ca-box", "address": "127.0.0.1", "os_family": "linux", "ports": map[string]int{"ssh": srv.port}}, e.admin)
	if code != 201 {
		t.Fatalf("create: %d %v", code, body)
	}
	id := body["id"].(string)
	if code, body := e.do("POST", "/api/v1/targets/"+id+"/probe-certificate", nil, e.admin); code != 409 || body["code"] != "host_key_untrusted" {
		t.Fatalf("before trust: %d %v", code, body)
	}
	if code, _ := e.do("POST", "/api/v1/targets/"+id+"/probe", nil, e.admin); code != 200 {
		t.Fatalf("probe: %d", code)
	}
	if code, _ := e.do("POST", "/api/v1/targets/"+id+"/host-key/trust", map[string]string{"host_key_fingerprint": srv.fp}, e.admin); code != 200 {
		t.Fatalf("trust: %d", code)
	}
	if code, body := e.do("POST", "/api/v1/targets/"+id+"/probe-certificate", nil, e.admin); code != 409 || body["code"] != "no_credential" {
		t.Fatalf("no credential: %d %v", code, body)
	}
	pw := &credential.Credential{Name: "pw", Type: credential.TypePassword, Mode: credential.ModeVaulted, Username: "root"}
	if err := e.vault.Create(ctx, pw, &credential.Secret{Password: "hunter2hunter2"}, ""); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.do("PUT", "/api/v1/targets/"+id+"/credentials/ssh", map[string]string{"credential_id": pw.ID}, e.admin); code != 200 {
		t.Fatalf("bind password: %d", code)
	}
	if code, body := e.do("POST", "/api/v1/targets/"+id+"/probe-certificate", nil, e.admin); code != 409 || body["code"] != "not_certificate_authority" {
		t.Fatalf("password credential: %d %v", code, body)
	}

	caPEM, _ := credential.GenerateSSHKey()
	ca := &credential.Credential{Name: "ca", Type: credential.TypeSSHCA, Mode: credential.ModeVaulted, Username: "deploy"}
	if err := e.vault.Create(ctx, ca, &credential.Secret{PrivateKey: caPEM}, ""); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.do("PUT", "/api/v1/targets/"+id+"/credentials/ssh", map[string]string{"credential_id": ca.ID}, e.admin); code != 200 {
		t.Fatalf("bind ca: %d", code)
	}
	// The target does not trust the authority yet: a real refusal, not an error.
	code, body = e.do("POST", "/api/v1/targets/"+id+"/probe-certificate", nil, e.admin)
	if code != 200 || body["accepted"] != false || body["reason"] != "certificate_rejected" || body["login_user"] != "deploy" || body["key"] != "current" {
		t.Fatalf("untrusted authority: %d %v", code, body)
	}
	srv.trust(ca.PublicKey)
	if code, body = e.do("POST", "/api/v1/targets/"+id+"/probe-certificate", map[string]string{"key": "current"}, e.admin); code != 200 || body["accepted"] != true {
		t.Fatalf("trusted authority: %d %v", code, body)
	}
	if code, body = e.do("POST", "/api/v1/targets/"+id+"/probe-certificate", map[string]string{"key": "pending"}, e.admin); code != 409 || body["code"] != "no_rotation" {
		t.Fatalf("pending without a rotation: %d %v", code, body)
	}
	if code, body = e.do("POST", "/api/v1/targets/"+id+"/probe-certificate", map[string]string{"key": "other"}, e.admin); code != 400 {
		t.Fatalf("bad key: %d %v", code, body)
	}

	// Rotation: the prepared key is rejected until the target trusts it too,
	// and the current key keeps working throughout.
	next, _ := credential.GenerateSSHKey()
	prepared, err := e.vault.PrepareRotation(ctx, ca.ID, &credential.Secret{PrivateKey: next})
	if err != nil {
		t.Fatal(err)
	}
	if code, body = e.do("POST", "/api/v1/targets/"+id+"/probe-certificate", map[string]string{"key": "pending"}, e.admin); code != 200 || body["accepted"] != false || body["key"] != "pending" {
		t.Fatalf("pending before the target trusts it: %d %v", code, body)
	}
	srv.trust(prepared.Rotation.PendingPublicKey)
	if code, body = e.do("POST", "/api/v1/targets/"+id+"/probe-certificate", map[string]string{"key": "pending"}, e.admin); code != 200 || body["accepted"] != true {
		t.Fatalf("pending once trusted: %d %v", code, body)
	}
	if _, err := e.vault.CutOver(ctx, ca.ID); err != nil {
		t.Fatal(err)
	}
	if code, body = e.do("POST", "/api/v1/targets/"+id+"/probe-certificate", nil, e.admin); code != 200 || body["accepted"] != true {
		t.Fatalf("current after cut over: %d %v", code, body)
	}
	// The allowlist applies to the probe's login user as well.
	if _, err := e.vault.Update(ctx, ca.ID, credential.Metadata{Name: "ca", Username: "deploy", CertificatePrincipals: []string{"ops"}}); err != nil {
		t.Fatal(err)
	}
	if code, body = e.do("POST", "/api/v1/targets/"+id+"/probe-certificate", nil, e.admin); code != 403 || body["code"] != "login_user_not_permitted" {
		t.Fatalf("allowlist: %d %v", code, body)
	}
	if code, _ := e.do("POST", "/api/v1/targets/"+id+"/probe-certificate", nil, e.user); code != 403 {
		t.Fatalf("non-admin must be refused, got %d", code)
	}

	events, _, err := e.audit.List(ctx, audit.Filter{Action: "target.probe.certificate"})
	if err != nil {
		t.Fatal(err)
	}
	var ok, failed int
	for _, ev := range events {
		if !strings.Contains(string(ev.Details), `"login_user":"deploy"`) {
			t.Fatalf("event should name the login user: %s", ev.Details)
		}
		if ev.Outcome == audit.Success {
			ok++
		} else {
			failed++
		}
	}
	if ok != 3 || failed != 2 {
		t.Fatalf("audited probes: %d accepted, %d refused, want 3 and 2", ok, failed)
	}
}
