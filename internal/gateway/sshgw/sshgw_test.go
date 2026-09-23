// SPDX-License-Identifier: Apache-2.0

package sshgw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/albatroxxx/zanskar/internal/recording"
)

// fakeServer is a minimal SSH server: password or public key auth, one
// session channel with a pty that upper-cases whatever it receives and
// exits on "exit".
type fakeServer struct {
	addr        string
	fingerprint string
	clientKey   ssh.Signer
}

func startFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientSigner, _ := ssh.NewSignerFromKey(clientPriv)
	allowed := clientSigner.PublicKey().Marshal()

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == "test" && string(pw) == "pw" {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == "test" && bytes.Equal(key.Marshal(), allowed) {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveConn(conn, cfg)
		}
	}()
	return &fakeServer{addr: ln.Addr().String(), fingerprint: ssh.FingerprintSHA256(hostSigner.PublicKey()), clientKey: clientSigner}
}

func serveConn(nc net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range creqs {
				switch r.Type {
				case "pty-req", "shell", "window-change":
					if r.WantReply {
						_ = r.Reply(true, nil)
					}
					if r.Type == "shell" {
						go shell(ch)
					}
				case "subsystem":
					name := ""
					if len(r.Payload) >= 4 {
						name = string(r.Payload[4:])
					}
					ok := name == "sftp"
					if r.WantReply {
						_ = r.Reply(ok, nil)
					}
					if ok {
						go func() {
							if srv, err := sftp.NewServer(ch); err == nil {
								_ = srv.Serve()
							}
							_ = ch.Close()
						}()
					}
				default:
					if r.WantReply {
						_ = r.Reply(false, nil)
					}
				}
			}
		}()
	}
}

func shell(ch ssh.Channel) {
	defer ch.Close()
	_, _ = ch.Write([]byte("$ "))
	buf := make([]byte, 256)
	var line []byte
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return
		}
		line = append(line, buf[:n]...)
		if i := bytes.IndexByte(line, '\r'); i >= 0 {
			cmd := strings.TrimSpace(string(line[:i]))
			line = line[i+1:]
			if cmd == "exit" {
				status := make([]byte, 4)
				binary.BigEndian.PutUint32(status, 0)
				_, _ = ch.SendRequest("exit-status", false, status)
				return
			}
			_, _ = ch.Write([]byte("\r\n" + strings.ToUpper(cmd) + "\r\n$ "))
		}
	}
}

func endpoint(fs *fakeServer, trusted bool) Endpoint {
	host, port, _ := net.SplitHostPort(fs.addr)
	var p int
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	return Endpoint{Address: host, Port: p, HostKeyFingerprint: fs.fingerprint, HostKeyTrusted: trusted}
}

func TestDialHostKeyAndAuth(t *testing.T) {
	fs := startFakeServer(t)
	ctx := context.Background()
	pw := Auth{Username: "test", Password: "pw"}

	if _, err := Dial(ctx, endpoint(fs, false), pw, time.Second); !errors.Is(err, ErrHostKeyUntrusted) {
		t.Fatalf("untrusted: %v", err)
	}
	bad := endpoint(fs, true)
	bad.HostKeyFingerprint = "SHA256:nope"
	if _, err := Dial(ctx, bad, pw, time.Second); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	if _, err := Dial(ctx, endpoint(fs, true), Auth{Username: "test", Password: "wrong"}, time.Second); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("bad password: %v", err)
	}
	if _, err := Dial(ctx, endpoint(fs, true), Auth{Username: "test"}, time.Second); !errors.Is(err, ErrNoAuth) {
		t.Fatalf("no auth: %v", err)
	}
	c, err := Dial(ctx, endpoint(fs, true), pw, time.Second)
	if err != nil {
		t.Fatalf("password dial: %v", err)
	}
	_ = c.Close()
}

func TestDialWithKey(t *testing.T) {
	fs := startFakeServer(t)
	// The server only trusts the key it generated; a fresh key must be
	// refused, proving the key path is exercised end to end.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pemEncode(block.Type, block.Bytes)
	if _, err := Dial(context.Background(), endpoint(fs, true), Auth{Username: "test", PrivateKey: pemBytes}, time.Second); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("unknown key should fail auth: %v", err)
	}
	if _, err := Dial(context.Background(), endpoint(fs, true), Auth{Username: "test", PrivateKey: []byte("garbage")}, time.Second); err == nil {
		t.Fatal("garbage key must error")
	}
}

func pemEncode(typ string, b []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("-----BEGIN " + typ + "-----\n")
	enc := make([]byte, base64Len(len(b)))
	base64Encode(enc, b)
	for i := 0; i < len(enc); i += 64 {
		end := i + 64
		if end > len(enc) {
			end = len(enc)
		}
		buf.Write(enc[i:end])
		buf.WriteByte('\n')
	}
	buf.WriteString("-----END " + typ + "-----\n")
	return buf.Bytes()
}

func TestBridgeEchoExitAndRecording(t *testing.T) {
	fs := startFakeServer(t)
	st := &recording.LocalStorage{Dir: t.TempDir()}
	var (
		reasonCh = make(chan string, 1)
		recCh    = make(chan *recording.Asciicast, 1)
		tapped   = &tapBuf{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		client, err := Dial(r.Context(), endpoint(fs, true), Auth{Username: "test", Password: "pw"}, time.Second)
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		defer func() { _ = client.Close() }()
		rec, _, err := recording.NewAsciicast(r.Context(), st, "s.cast", recording.Header{Width: 80, Height: 24})
		if err != nil {
			t.Errorf("rec: %v", err)
			return
		}
		reason, err := Bridge(r.Context(), nil, client, ws, rec, 80, 24, Limits{Idle: time.Minute, Tap: tapped})
		if err != nil {
			t.Errorf("bridge: %v", err)
		}
		reasonCh <- reason
		recCh <- rec
		_ = ws.Close(websocket.StatusNormalClosure, "")
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose // library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()

	readUntil := func(want string) {
		var acc string
		for !strings.Contains(acc, want) {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				t.Fatalf("read waiting for %q: %v (got %q)", want, err, acc)
			}
			if typ == websocket.MessageBinary {
				acc += string(data)
			} else {
				var c control
				_ = json.Unmarshal(data, &c)
				if c.T == "end" {
					t.Fatalf("unexpected end %q while waiting for %q (got %q)", c.Reason, want, acc)
				}
			}
		}
	}
	// ready control frame first
	typ, data, err := ws.Read(ctx)
	if err != nil || typ != websocket.MessageText || !strings.Contains(string(data), `"ready"`) {
		t.Fatalf("expected ready, got %v %s %v", typ, data, err)
	}
	readUntil("$ ")
	send := func(f clientFrame) {
		b, _ := json.Marshal(f)
		if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
			t.Fatal(err)
		}
	}
	send(clientFrame{T: "r", Cols: 120, Rows: 40})
	send(clientFrame{T: "i", D: "hello\r"})
	readUntil("HELLO")
	send(clientFrame{T: "i", D: "exit\r"})

	// Expect the end control frame.
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for end: %v", err)
		}
		if typ == websocket.MessageText {
			var c control
			_ = json.Unmarshal(data, &c)
			if c.T == "end" {
				if c.Reason != "user_exit" {
					t.Fatalf("reason %q", c.Reason)
				}
				break
			}
		}
	}
	if r := <-reasonCh; r != "user_exit" {
		t.Fatalf("bridge reason %q", r)
	}
	rec := <-recCh
	size, sum, err := rec.Close()
	if err != nil || size == 0 || sum == "" {
		t.Fatalf("recording close: %d %q %v", size, sum, err)
	}
	if !strings.Contains(tapped.String(), "HELLO") {
		t.Fatalf("tap did not receive session output: %q", tapped.String())
	}
}

func TestBridgeIdleTimeout(t *testing.T) {
	fs := startFakeServer(t)
	reasonCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		client, err := Dial(r.Context(), endpoint(fs, true), Auth{Username: "test", Password: "pw"}, time.Second)
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		defer func() { _ = client.Close() }()
		reason, _ := Bridge(r.Context(), nil, client, ws, nil, 80, 24, Limits{Idle: 200 * time.Millisecond, tick: 50 * time.Millisecond})
		reasonCh <- reason
		_ = ws.Close(websocket.StatusNormalClosure, "")
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil) //nolint:bodyclose // library closes the handshake body
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			break
		}
		if typ == websocket.MessageText && strings.Contains(string(data), `"idle_timeout"`) {
			break
		}
	}
	select {
	case r := <-reasonCh:
		if r != "idle_timeout" {
			t.Fatalf("reason %q", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bridge did not end")
	}
}

// tiny base64 helpers so the test file has no extra imports to keep tidy.
const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func base64Len(n int) int { return (n + 2) / 3 * 4 }

func base64Encode(dst, src []byte) {
	di := 0
	for i := 0; i < len(src); i += 3 {
		var v uint32
		rem := len(src) - i
		for j := 0; j < 3; j++ {
			v <<= 8
			if j < rem {
				v |= uint32(src[i+j])
			}
		}
		for j := 0; j < 4; j++ {
			if j <= rem {
				dst[di] = b64[(v>>(18-6*j))&63]
			} else {
				dst[di] = '='
			}
			di++
		}
	}
}

// tapBuf collects tapped output for the shadowing assertion.
type tapBuf struct {
	mu sync.Mutex
	b  []byte
}

func (t *tapBuf) Write(p []byte) { t.mu.Lock(); t.b = append(t.b, p...); t.mu.Unlock() }
func (t *tapBuf) String() string { t.mu.Lock(); defer t.mu.Unlock(); return string(t.b) }
