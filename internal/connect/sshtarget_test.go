// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeSSHTarget starts an SSH server on loopback that accepts one username
// and password and hands each session channel, with its requests, to serve.
// It returns the listening port and the host key's fingerprint and public key.
func fakeSSHTarget(t *testing.T, username, password string, serve func(ssh.Channel, <-chan *ssh.Request)) (int, string, ssh.PublicKey) {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == username && string(pw) == password {
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
					go serve(ch, creqs)
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ssh.FingerprintSHA256(hostSigner.PublicKey()), hostSigner.PublicKey()
}

// postConnect asks a real server at baseURL for a ticket as alice and returns
// the decoded response and its status.
func (f *connectFixture) postConnect(t *testing.T, baseURL, targetID, proto string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"target_id": targetID, "protocol": proto})
	req, _ := http.NewRequest("POST", baseURL+"/api/v1/connect", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", f.csrf)
	req.AddCookie(f.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}
