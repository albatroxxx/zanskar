// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/albatroxxx/zanskar/internal/target"
)

// keyOnlySSHTarget is an SSH server that lets username in with the one public
// key it is given and refuses every password, so a session that reaches its
// shell proves the user's own key signed in.
func keyOnlySSHTarget(t *testing.T, username string, allowed ssh.PublicKey) (int, string) {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if c.User() == username && bytes.Equal(k.Marshal(), allowed.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				defer func() { _ = sc.Close() }()
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					ch, creqs, err := newCh.Accept()
					if err != nil {
						return
					}
					go func() {
						for r := range creqs {
							if r.WantReply {
								_ = r.Reply(r.Type == "pty-req" || r.Type == "shell" || r.Type == "window-change", nil)
							}
							if r.Type == "shell" {
								go upperShell(ch)
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ssh.FingerprintSHA256(hostSigner.PublicKey())
}

// encryptedKey makes an ed25519 key and returns its public half and its
// private half in OpenSSH PEM, encrypted with passphrase.
func encryptedKey(t *testing.T, passphrase string) (ssh.PublicKey, string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	return sshPub, string(pem.EncodeToMemory(block))
}

// TestUserSuppliedKeyEndToEnd (2026-10-30): on a target whose slot asks the
// user for their own login, a user may sign in over SSH with their own
// private key and its passphrase instead of a password. The key is unlocked
// when the ticket is issued and signs in when it is redeemed; the target
// here refuses every password, so its shell answering proves the key did.
func TestUserSuppliedKeyEndToEnd(t *testing.T) {
	pub, keyPEM := encryptedKey(t, "correct horse")
	port, fp := keyOnlySSHTarget(t, "alice-own", pub)
	r := newTerminalRig(t, port, fp)
	own, err := r.h.Vault.EnsureUserSupplied(r.ctx, r.alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := r.h.Targets.Get(r.ctx, r.targetID)
	if err != nil {
		t.Fatal(err)
	}
	tg.Credentials = map[target.Protocol]string{target.SSH: own}
	if err := r.h.Targets.Update(r.ctx, tg); err != nil {
		t.Fatal(err)
	}

	post := func(cred map[string]string) (int, map[string]any) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"target_id": r.targetID, "protocol": "ssh", "credential": cred})
		req, _ := http.NewRequest("POST", r.url+"/api/v1/connect", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", r.csrf)
		req.AddCookie(r.cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	// A wrong or missing passphrase is a plain answer before any socket.
	for _, pass := range []string{"", "wrong"} {
		code, out := post(map[string]string{"username": "alice-own", "private_key": keyPEM, "private_key_passphrase": pass})
		if code != http.StatusUnprocessableEntity || out["code"] != "credential_invalid" || !strings.Contains(out["message"].(string), "passphrase") {
			t.Fatalf("passphrase %q: %d %v", pass, code, out)
		}
	}
	// Not a key at all.
	if code, out := post(map[string]string{"username": "alice-own", "private_key": "-----BEGIN NOTHING-----\nAAAA\n-----END NOTHING-----"}); code != http.StatusUnprocessableEntity || out["code"] != "credential_invalid" {
		t.Fatalf("garbage key: %d %v", code, out)
	}
	// Larger than any key: refused before it is parsed.
	if code, out := post(map[string]string{"username": "alice-own", "private_key": strings.Repeat("A", maxUserKey+1)}); code != http.StatusUnprocessableEntity || out["message"] != "the private key is too large" {
		t.Fatalf("oversized key: %d %v", code, out)
	}

	code, out := post(map[string]string{"username": "alice-own", "private_key": keyPEM, "private_key_passphrase": "correct horse"})
	tok, _ := out["ticket"].(string)
	if code != http.StatusOK || tok == "" {
		t.Fatalf("connect with the key: %d %v", code, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, _, err := r.dial(ctx, tok) //nolint:bodyclose // the library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	_, output, reason := runShell(t, ctx, ws, nil)
	if !strings.Contains(output, "HELLO") || reason != "user_exit" {
		t.Fatalf("the key did not open the shell: reason %q, output %q", reason, output)
	}
}

// TestUserSuppliedKeyIsForSSHOnly: a key signs in over SSH alone; a WinRM
// slot asking for the user's login takes a password, and says so.
func TestUserSuppliedKeyIsForSSHOnly(t *testing.T) {
	f := newConnectFixture(t)
	own, err := f.h.Vault.EnsureUserSupplied(f.ctx, f.alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	tg := &target.Target{Name: "win-own", Address: "10.0.0.9", OSFamily: target.Windows, Tags: map[string]string{"env": "test"},
		Credentials: map[target.Protocol]string{target.WinRM: own}}
	if err := f.h.Targets.Create(f.ctx, tg); err != nil {
		t.Fatal(err)
	}
	// The first certificate a probe captures is pinned (ADR 0012).
	const certFP = "bb22"
	if _, _, err := f.h.Targets.RecordProbe(f.ctx, tg.ID, target.ProbeResult{Address: tg.Address, ResolvedIP: tg.Address, Capabilities: []target.Protocol{target.WinRM},
		WinRMTLS: &target.TLSInfo{Fingerprint: certFP, Source: "winrm"}}); err != nil {
		t.Fatal(err)
	}

	_, keyPEM := encryptedKey(t, "pp")
	code, out := f.connect(t, map[string]any{"target_id": tg.ID, "protocol": "winrm", "credential": map[string]string{"username": "alice", "private_key": keyPEM, "private_key_passphrase": "pp"}})
	if code != http.StatusUnprocessableEntity || out["code"] != "credential_required" || !strings.Contains(out["message"].(string), "SSH only") {
		t.Fatalf("a key over WinRM: %d %v", code, out)
	}
}
