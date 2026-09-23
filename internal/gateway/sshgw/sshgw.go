// SPDX-License-Identifier: Apache-2.0

// Package sshgw opens SSH sessions to targets and bridges them to a browser
// terminal over WebSocket, recording output as it flows. The browser never
// sees the target address or the credential; it only sees bytes.
package sshgw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/recording"
)

// Endpoint describes where to connect and which host key to expect.
type Endpoint struct {
	Address            string
	Port               int
	HostKeyFingerprint string // SHA256:... as stored on the target
	HostKeyTrusted     bool   // only trusted keys may be connected to
}

// Auth is how Zanskar authenticates to the target (ADR 0005).
type Auth struct {
	Username   string
	Password   string
	PrivateKey []byte // PEM; takes precedence over Password when set
	// Certificate is an SSH certificate for PrivateKey, when using the CA mode.
	Certificate []byte
}

// Errors the connect handler maps to user-facing messages.
var (
	ErrHostKeyUntrusted = errors.New("sshgw: host key not yet trusted by an admin")
	ErrHostKeyMismatch  = errors.New("sshgw: host key does not match the trusted fingerprint")
	ErrAuthFailed       = errors.New("sshgw: authentication to target failed")
	ErrNoAuth           = errors.New("sshgw: no credential material")
)

// Dial connects and authenticates. It refuses to proceed unless the server
// presents exactly the trusted host key: no TOFU at connect time.
func Dial(ctx context.Context, ep Endpoint, a Auth, timeout time.Duration) (*ssh.Client, error) {
	if !ep.HostKeyTrusted || ep.HostKeyFingerprint == "" {
		return nil, ErrHostKeyUntrusted
	}
	methods, err := authMethods(a)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:    a.Username,
		Auth:    methods,
		Timeout: timeout,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != ep.HostKeyFingerprint {
				return ErrHostKeyMismatch
			}
			return nil
		},
	}
	addr := net.JoinHostPort(ep.Address, strconv.Itoa(ep.Port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sshgw: dial: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		if errors.Is(err, ErrHostKeyMismatch) {
			return nil, ErrHostKeyMismatch
		}
		return nil, fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

func authMethods(a Auth) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if len(a.PrivateKey) > 0 {
		signer, err := ssh.ParsePrivateKey(a.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("sshgw: private key: %w", err)
		}
		if len(a.Certificate) > 0 {
			pub, _, _, _, err := ssh.ParseAuthorizedKey(a.Certificate)
			if err != nil {
				return nil, fmt.Errorf("sshgw: certificate: %w", err)
			}
			cert, ok := pub.(*ssh.Certificate)
			if !ok {
				return nil, errors.New("sshgw: certificate is not an SSH certificate")
			}
			if signer, err = ssh.NewCertSigner(cert, signer); err != nil {
				return nil, err
			}
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if a.Password != "" {
		pw := a.Password
		methods = append(methods, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = pw
			}
			return answers, nil
		}))
	}
	if len(methods) == 0 {
		return nil, ErrNoAuth
	}
	return methods, nil
}

// Limits bound a live session, taken from the policy decision.
type Limits struct {
	// SessionID is echoed in the ready frame so the browser can address the
	// session later (failover, shadowing, file transfer).
	SessionID string
	// AllowFiles is echoed in the ready frame so the terminal shows the files
	// panel only when the policy permits SFTP transfer (ADR 0016).
	AllowFiles bool
	Idle       time.Duration // ends the session after this long without input
	Max        time.Duration // absolute cap from start; zero means none
	// Tap, when set, receives every output chunk after it is recorded, so
	// auditors can shadow the session live. Writes must never block.
	Tap  interface{ Write([]byte) }
	tick time.Duration // how often limits are checked; tests shorten it
}

// clientFrame is what the browser sends as a text message.
type clientFrame struct {
	T    string `json:"t"` // "i" input, "r" resize, "p" ping
	D    string `json:"d,omitempty"`
	Cols int    `json:"c,omitempty"`
	Rows int    `json:"r,omitempty"`
}

// control is what the server sends as a text message. Output is sent as
// binary frames so it needs no framing at all.
type control struct {
	T         string `json:"t"` // "ready", "end"
	SessionID string `json:"session_id,omitempty"`
	Files     bool   `json:"files,omitempty"` // file transfer allowed (ADR 0016)
	Reason    string `json:"reason,omitempty"`
	Msg       string `json:"msg,omitempty"`
}

// Bridge runs an interactive shell over the client and pumps it to the
// WebSocket until one side ends. It returns the end reason for the
// access_sessions row. rec may be nil.
func Bridge(ctx context.Context, log *slog.Logger, client *ssh.Client, ws *websocket.Conn, rec *recording.Asciicast, cols, rows int, lim Limits) (string, error) {
	if log == nil {
		log = slog.Default()
	}
	sess, err := client.NewSession()
	if err != nil {
		return "error", err
	}
	defer func() { _ = sess.Close() }()
	if cols <= 0 || cols > 1000 {
		cols = 80
	}
	if rows <= 0 || rows > 500 {
		rows = 24
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 115200, ssh.TTY_OP_OSPEED: 115200}
	if err := sess.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		return "error", fmt.Errorf("pty: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return "error", err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return "error", err
	}
	sess.Stderr = sess.Stdout // merge; the pty already does this on most servers
	if err := sess.Shell(); err != nil {
		return "error", fmt.Errorf("shell: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu     sync.Mutex
		reason = "user_exit"
		lastIn = time.Now()
		start  = time.Now()
		setEnd = func(r string) {
			mu.Lock()
			if reason == "user_exit" {
				reason = r
			}
			mu.Unlock()
		}
		current = func() string { mu.Lock(); defer mu.Unlock(); return reason }
		outDone = make(chan struct{})
		inDone  = make(chan struct{})
	)
	// The final frame must go out even after ctx is cancelled, so it gets
	// its own short deadline.
	sendCtrl := func(c control) {
		b, _ := json.Marshal(c)
		wctx, wcancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer wcancel()
		_ = ws.Write(wctx, websocket.MessageText, b)
	}
	sendCtrl(control{T: "ready", SessionID: lim.SessionID, Files: lim.AllowFiles})

	// Submitted command lines become markers on the recording so a reviewer
	// can list them; input the remote did not echo is recorded as hidden.
	var cmds *commandLog
	if rec != nil {
		cmds = newCommandLog(func(label string) { _ = rec.Marker(label) })
	}

	// target -> browser (+ recording)
	go func() {
		defer close(outDone)
		buf := make([]byte, 32<<10)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				if rec != nil {
					if rerr := rec.Output(buf[:n]); rerr != nil {
						log.Error("recording write failed; ending session", "err", rerr)
						setEnd("error")
						return
					}
				}
				if cmds != nil {
					cmds.output(buf[:n])
				}
				if lim.Tap != nil {
					lim.Tap.Write(buf[:n])
				}
				if werr := ws.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) && ctx.Err() == nil {
					setEnd("target_lost")
				}
				return
			}
		}
	}()

	// browser -> target
	go func() {
		defer close(inDone)
		for {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			mu.Lock()
			lastIn = time.Now()
			mu.Unlock()
			if typ == websocket.MessageBinary {
				if cmds != nil {
					cmds.input(data)
				}
				if _, err := stdin.Write(data); err != nil {
					return
				}
				continue
			}
			var f clientFrame
			if json.Unmarshal(data, &f) != nil {
				continue
			}
			switch f.T {
			case "i":
				if cmds != nil {
					cmds.input([]byte(f.D))
				}
				if rec != nil {
					_ = rec.Input([]byte(f.D))
				}
				if _, err := stdin.Write([]byte(f.D)); err != nil {
					return
				}
			case "r":
				if f.Cols > 0 && f.Rows > 0 && f.Cols <= 1000 && f.Rows <= 500 {
					_ = sess.WindowChange(f.Rows, f.Cols)
					if rec != nil {
						_ = rec.Resize(f.Cols, f.Rows)
					}
				}
			}
		}
	}()

	waitDone := make(chan error, 1)
	go func() { waitDone <- sess.Wait() }()
	if lim.tick <= 0 {
		lim.tick = 5 * time.Second
	}
	ticker := time.NewTicker(lim.tick)
	defer ticker.Stop()

	finish := func(r, msg string) (string, error) {
		setEnd(r)
		r = current()
		sendCtrl(control{T: "end", Reason: r, Msg: msg})
		cancel()
		return r, nil
	}
	for {
		select {
		case <-ctx.Done():
			// Cancelled by the registry: admin terminate, policy revocation, or
			// the sync loop retiring the instance. The cause says which.
			reason, msg := gateway.CancelReason(ctx)
			return finish(reason, msg)
		case <-inDone:
			// Browser went away (tab closed, network drop). Nothing to send.
			r := current()
			cancel()
			return r, nil
		case err := <-waitDone:
			// Remote shell exited: the user typed exit, or the host went away.
			var exitErr *ssh.ExitError
			if err != nil && !errors.As(err, &exitErr) && !errors.Is(err, io.EOF) {
				setEnd("target_lost")
			}
			<-outDone // drain remaining output before the end frame
			return finish("user_exit", "")
		case <-outDone:
			// Output closed before the shell reported exit; treat as lost
			// unless the reason was already decided.
			if r := current(); r != "user_exit" {
				return finish(r, "connection to the target was lost")
			}
			select {
			case <-waitDone:
			case <-time.After(2 * time.Second):
				setEnd("target_lost")
			}
			return finish("user_exit", "")
		case now := <-ticker.C:
			mu.Lock()
			idle := now.Sub(lastIn)
			mu.Unlock()
			if lim.Idle > 0 && idle > lim.Idle {
				return finish("idle_timeout", "disconnected after "+lim.Idle.String()+" without input")
			}
			if lim.Max > 0 && now.Sub(start) > lim.Max {
				return finish("max_duration", "session reached the policy's maximum duration")
			}
		}
	}
}
