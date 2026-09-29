// SPDX-License-Identifier: Apache-2.0

// Command fakessh is a throwaway SSH server for local development and the
// smoke test. It accepts password auth (test / pw) and, with -ca-pub, user
// certificates signed by that authority, the way sshd does with
// TrustedUserCAKeys. Every session gets a toy shell that upper-cases each
// line and exits on "exit". It is not a real shell: no processes are
// spawned, nothing touches the host.
//
//	go run ./hack/fakessh [-hostkey path] [-ca-pub path] [listen-addr]   (default 0.0.0.0:2222)
//
// With -hostkey the host key is loaded from, or generated and saved to, that
// file so restarts keep the same fingerprint and pinned targets stay valid.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

func main() {
	keyPath := flag.String("hostkey", "", "path to persist the host key (generated if missing)")
	caPath := flag.String("ca-pub", "", "authorized_keys line of a CA whose user certificates are accepted (like TrustedUserCAKeys)")
	flag.Parse()
	signer, err := hostKey(*keyPath)
	if err != nil {
		panic(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == "test" && string(pw) == "pw" {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	if *caPath != "" {
		if _, err := trustedAuthorities(*caPath); err != nil {
			panic(err)
		}
		// The file is re-read on every attempt and may hold several keys, so
		// a rotation can be rehearsed by appending the next key, as an
		// operator would edit TrustedUserCAKeys. CertChecker verifies the
		// signature, the validity window and that the login user is among the
		// certificate's principals, as sshd does.
		checker := &ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool {
			cas, err := trustedAuthorities(*caPath)
			if err != nil {
				return false
			}
			for _, ca := range cas {
				if bytes.Equal(k.Marshal(), ca.Marshal()) {
					return true
				}
			}
			return false
		}}
		cfg.PublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			perms, err := checker.Authenticate(c, key)
			if err != nil {
				fmt.Println("certificate refused for", c.User()+":", err)
				return nil, err
			}
			if cert, ok := key.(*ssh.Certificate); ok {
				fmt.Println("accepted certificate for", c.User(), "key id", cert.KeyId)
			}
			return perms, nil
		}
		fmt.Println("trusting user certificates from", *caPath)
	}
	cfg.AddHostKey(signer)
	addr := "0.0.0.0:2222"
	if flag.NArg() > 0 {
		addr = flag.Arg(0)
	}
	// A demo server must be reachable from the gateway's LAN address, since
	// the probe refuses loopback targets; hence the all-interfaces default.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr) // #nosec G102 -- dev tool, see comment
	if err != nil {
		panic(err)
	}
	fmt.Println("listening", addr, "fingerprint", ssh.FingerprintSHA256(signer.PublicKey()))
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go serve(c, cfg)
	}
}

// trustedAuthorities parses every authorized_keys line in the file.
func trustedAuthorities(path string) ([]ssh.PublicKey, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-chosen dev path
	if err != nil {
		return nil, err
	}
	var out []ssh.PublicKey
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("ca-pub: %w", err)
		}
		out = append(out, pub)
	}
	if len(out) == 0 {
		return nil, errors.New("ca-pub: no keys in file")
	}
	return out, nil
}

func hostKey(path string) (ssh.Signer, error) {
	if path != "" {
		if raw, err := os.ReadFile(path); err == nil { // #nosec G304 -- operator-chosen dev path
			return ssh.ParsePrivateKey(raw)
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if path != "" {
		block, err := ssh.MarshalPrivateKey(priv, "fakessh host key")
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			return nil, err
		}
	}
	return ssh.NewSignerFromKey(priv)
}

func serve(nc net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range creqs {
				if r.WantReply {
					_ = r.Reply(true, nil)
				}
				if r.Type == "shell" {
					go shell(ch)
				}
			}
		}()
	}
}

// shell is a tiny line editor: printable characters echo, backspace and
// delete erase, Ctrl-U clears the line, Ctrl-C abandons it, Ctrl-D or
// "exit" ends the session, Enter runs the "command" (upper-casing it).
func shell(ch ssh.Channel) {
	defer func() { _ = ch.Close() }()
	_, _ = ch.Write([]byte("welcome to fakessh (type exit to leave)\r\n$ "))
	buf := make([]byte, 256)
	var line []byte
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return
		}
		for _, b := range buf[:n] {
			switch {
			case b == '\r' || b == '\n':
				cmd := strings.TrimSpace(string(line))
				line = line[:0]
				if cmd == "exit" {
					_, _ = ch.Write([]byte("\r\nbye\r\n"))
					exit(ch)
					return
				}
				if cmd == "" {
					_, _ = ch.Write([]byte("\r\n$ "))
					continue
				}
				_, _ = ch.Write([]byte("\r\n" + strings.ToUpper(cmd) + "\r\n$ "))
			case b == 0x7f || b == 0x08: // backspace / delete
				if len(line) > 0 {
					line = line[:len(line)-1]
					_, _ = ch.Write([]byte("\b \b"))
				}
			case b == 0x15: // Ctrl-U
				_, _ = ch.Write(bytes.Repeat([]byte("\b \b"), len(line)))
				line = line[:0]
			case b == 0x03: // Ctrl-C
				line = line[:0]
				_, _ = ch.Write([]byte("^C\r\n$ "))
			case b == 0x04: // Ctrl-D
				_, _ = ch.Write([]byte("\r\nbye\r\n"))
				exit(ch)
				return
			case b >= 0x20 && b < 0x7f:
				line = append(line, b)
				_, _ = ch.Write([]byte{b})
			}
		}
	}
}

func exit(ch ssh.Channel) {
	st := make([]byte, 4)
	binary.BigEndian.PutUint32(st, 0)
	_, _ = ch.SendRequest("exit-status", false, st)
}
