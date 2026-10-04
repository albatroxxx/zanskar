// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
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
