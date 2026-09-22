// SPDX-License-Identifier: Apache-2.0

// Package winrmgw gives Windows targets a browser terminal over WinRM without
// installing anything on the host. WinRM has no raw PTY, so this is a
// LINE-ORIENTED PowerShell console, not a character device: the browser's
// keystrokes are buffered into a line, echoed locally (WinRM does not echo),
// and each submitted line is executed as one PowerShell command whose stdout
// and stderr stream back. Interactive, cursor-driven TUIs will not work; a
// command prompt does. The WebSocket framing matches internal/gateway/sshgw
// exactly so the same browser terminal drives both.
package winrmgw

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/masterzen/winrm"

	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/recording"
)

// Endpoint describes the WinRM listener on the target.
type Endpoint struct {
	Address string
	Port    int  // 0 uses 5986 for TLS, 5985 otherwise
	UseTLS  bool // WinRM over HTTPS (required by the gateway; plain HTTP is refused)
	// PinnedFingerprint is the SHA-256 (hex) of the listener's leaf certificate
	// captured by the probe. When set, it is the only trust anchor: the CA and
	// hostname checks are replaced by an exact match, like SSH host key pinning.
	PinnedFingerprint string
	// CACertPEM verifies the listener against a CA bundle instead of a pin.
	CACertPEM string
	// Insecure skips verification entirely. Development only; Dial refuses
	// TLS endpoints that have neither a pin, a CA bundle, nor this flag.
	Insecure bool
}

// Auth is how Zanskar authenticates to the target (ADR 0005). A non-empty
// Domain selects NTLM, which is what Active Directory hosts expect.
type Auth struct {
	Username string
	Password string
	Domain   string
}

// Errors the connect handler maps to user-facing messages.
var (
	ErrAuthFailed = errors.New("winrmgw: authentication to target failed")
	ErrBadCACert  = errors.New("winrmgw: CA certificate is not valid PEM")
)

// Shell runs one command line at a time against the target. It is an
// interface so Bridge can be tested without a Windows host.
type Shell interface {
	// Run executes one line, streaming its stdout and stderr to the writers,
	// and returns the process exit code.
	Run(ctx context.Context, line string, stdout, stderr io.Writer) (int, error)
	Close() error
}

// Client is a dialed, authenticated WinRM connection.
type Client struct {
	wc *winrm.Client
}

// Dial builds a WinRM client and verifies it can execute a command, so a bad
// credential or unreachable host is an error before any WebSocket upgrade.
func Dial(ctx context.Context, ep Endpoint, a Auth, timeout time.Duration) (*Client, error) {
	port := ep.Port
	if port == 0 {
		if ep.UseTLS {
			port = 5986
		} else {
			port = 5985
		}
	}
	var caPEM []byte
	if ep.UseTLS && ep.CACertPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(ep.CACertPEM)) {
			return nil, ErrBadCACert
		}
		caPEM = []byte(ep.CACertPEM)
	}
	if ep.UseTLS && ep.PinnedFingerprint == "" && caPEM == nil && !ep.Insecure {
		return nil, ErrUnpinned
	}
	endpoint := winrm.NewEndpoint(ep.Address, port, ep.UseTLS, ep.Insecure, caPEM, nil, nil, timeout)

	params := winrm.NewParameters("PT60S", "en-US", 153600)
	user := a.Username
	ntlm := a.Domain != ""
	if ntlm {
		// NTLM for AD. WinRM sends DOMAIN\user; the NTLM transport handles
		// the handshake.
		params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
		if !strings.Contains(user, "\\") && !strings.Contains(user, "@") {
			user = a.Domain + "\\" + user
		}
	}
	if ep.UseTLS && ep.PinnedFingerprint != "" {
		pt, err := newPinnedTransport(ep.Address, port, user, a.Password, ep.PinnedFingerprint, ntlm)
		if err != nil {
			return nil, err
		}
		params.TransportDecorator = func() winrm.Transporter { return pt }
	}
	wc, err := winrm.NewClientWithParameters(endpoint, user, a.Password, params)
	if err != nil {
		return nil, fmt.Errorf("winrmgw: client: %w", err)
	}

	// Connectivity and credential check.
	vctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	code, err := wc.RunWithContext(vctx, winrm.Powershell("$Host.Name"), io.Discard, io.Discard)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}
	if code != 0 {
		return nil, ErrAuthFailed
	}
	return &Client{wc: wc}, nil
}

// Shell returns a line runner over the connection.
func (c *Client) Shell(_ context.Context) (Shell, error) {
	return &winrmShell{wc: c.wc}, nil
}

// winrmShell runs each line as a fresh PowerShell command. WinRM creates and
// tears down a remote shell per command; there is no persistent process, so
// state does not carry between lines. That is the trade-off of an agentless
// WinRM console and is documented on the package.
type winrmShell struct {
	wc *winrm.Client
}

func (s *winrmShell) Run(ctx context.Context, line string, stdout, stderr io.Writer) (int, error) {
	return s.wc.RunWithContext(ctx, winrm.Powershell(line), stdout, stderr)
}

// commandFailureEndsSession reports whether an error from running a single
// command means the target connection is gone (end the session) rather than
// just that the command itself failed (show it and stay at the prompt). A
// dropped connection or refused dial ends the session; an output-poll timeout
// or a command-level fault does not.
func commandFailureEndsSession(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "operationtimeout") {
		return false
	}
	for _, s := range []string{"eof", "connection refused", "connection reset", "no route to host", "network is unreachable", "broken pipe", "no such host"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

func (s *winrmShell) Close() error { return nil }

// Limits bound a live session, taken from the policy decision.
type Limits struct {
	// SessionID is echoed in the ready frame so the browser can address the
	// session later (failover, shadowing).
	SessionID string
	Idle      time.Duration // ends the session after this long without input
	Max       time.Duration // absolute cap from start; zero means none
	// Tap, when set, receives every output chunk for live shadowing.
	Tap  interface{ Write([]byte) }
	tick time.Duration // how often limits are checked; tests shorten it
}

type clientFrame struct {
	T    string `json:"t"`
	D    string `json:"d,omitempty"`
	Cols int    `json:"c,omitempty"`
	Rows int    `json:"r,omitempty"`
}

type control struct {
	T         string `json:"t"`
	SessionID string `json:"session_id,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Msg       string `json:"msg,omitempty"`
}

const prompt = "PS> "

// Bridge relays a line-oriented PowerShell console between the browser and the
// target until one side ends, returning the end reason for the session row.
// rec may be nil. cols and rows are accepted for protocol parity but unused.
func Bridge(ctx context.Context, log *slog.Logger, sh Shell, ws *websocket.Conn, rec *recording.Asciicast, cols, rows int, lim Limits) (string, error) {
	if log == nil {
		log = slog.Default()
	}
	_ = cols
	_ = rows
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu     sync.Mutex
		reason = "user_exit"
		lastIn = time.Now()
		start  = time.Now()
		wmu    sync.Mutex // serialises websocket writes
		setEnd = func(r string) {
			mu.Lock()
			if reason == "user_exit" {
				reason = r
			}
			mu.Unlock()
		}
		current = func() string { mu.Lock(); defer mu.Unlock(); return reason }
		touch   = func() { mu.Lock(); lastIn = time.Now(); mu.Unlock() }
	)

	out := func(b []byte) bool {
		if len(b) == 0 {
			return true
		}
		if rec != nil {
			if err := rec.Output(b); err != nil {
				log.Error("recording write failed; ending session", "err", err)
				setEnd("error")
				return false
			}
		}
		if lim.Tap != nil {
			lim.Tap.Write(b)
		}
		wmu.Lock()
		defer wmu.Unlock()
		return ws.Write(ctx, websocket.MessageBinary, b) == nil
	}
	sendCtrl := func(c control) {
		b, _ := json.Marshal(c)
		wctx, wcancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer wcancel()
		wmu.Lock()
		defer wmu.Unlock()
		_ = ws.Write(wctx, websocket.MessageText, b)
	}

	sendCtrl(control{T: "ready", SessionID: lim.SessionID})
	out([]byte(prompt))

	lineCh := make(chan string, 8)
	readerDone := make(chan struct{})

	// Reader: browser -> line buffer, with local echo and editing.
	go func() {
		defer close(readerDone)
		var line []byte
		feed := func(data []byte) bool {
			for _, b := range data {
				switch b {
				case '\r', '\n':
					out([]byte("\r\n"))
					select {
					case lineCh <- string(line):
					case <-ctx.Done():
						return false
					}
					line = line[:0]
				case 0x7f, 0x08: // backspace / delete
					if len(line) > 0 {
						line = line[:len(line)-1]
						out([]byte("\b \b"))
					}
				case 0x03: // Ctrl-C abandons the line
					line = line[:0]
					out([]byte("^C\r\n" + prompt))
				default:
					if b >= 0x20 {
						line = append(line, b)
						out([]byte{b})
					}
				}
			}
			return true
		}
		for {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			touch()
			if typ == websocket.MessageBinary {
				if !feed(data) {
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
				if !feed([]byte(f.D)) {
					return
				}
			case "r", "p":
				// resize is meaningless over WinRM; ping keeps the session
				// alive. Both already counted as activity via touch().
			}
		}
	}()

	// Executor: run submitted lines, stream output, reprint the prompt.
	execDone := make(chan struct{})
	go func() {
		defer close(execDone)
		sw := writerFunc(func(b []byte) (int, error) {
			if !out(b) {
				return 0, io.ErrClosedPipe
			}
			return len(b), nil
		})
		for {
			select {
			case <-ctx.Done():
				return
			case l, ok := <-lineCh:
				if !ok {
					return
				}
				trimmed := strings.TrimSpace(l)
				if trimmed == "" {
					out([]byte(prompt))
					continue
				}
				if strings.EqualFold(trimmed, "exit") {
					setEnd("user_exit")
					return
				}
				// Every submitted line is a command here (local echo, no hidden
				// prompts), so record it as a marker for the reviewer's list.
				if rec != nil {
					_ = rec.Marker(trimmed)
				}
				if _, err := sh.Run(ctx, trimmed, sw, sw); err != nil {
					if ctx.Err() != nil {
						return
					}
					if commandFailureEndsSession(err) {
						setEnd("target_lost")
						return
					}
					// A single command failing is not a lost target: surface the
					// error and keep the console open at a fresh prompt.
					log.Warn("winrm command error", "err", err)
					out([]byte("\r\n" + cleanCommandError(err) + "\r\n"))
				}
				out([]byte("\r\n" + prompt))
			}
		}
	}()

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
		_ = sh.Close()
		return r, nil
	}
	for {
		select {
		case <-ctx.Done():
			// Only external cancellation reaches here (admin terminate or a
			// revoked policy); the exit and idle paths return before this.
			reason, msg := gateway.CancelReason(ctx)
			return finish(reason, msg)
		case <-readerDone:
			// Browser went away.
			r := current()
			cancel()
			_ = sh.Close()
			return r, nil
		case <-execDone:
			// Executor stopped: "exit" typed or target lost.
			return finish(current(), msgFor(current()))
		case now := <-ticker.C:
			mu.Lock()
			idle := now.Sub(lastIn)
			elapsed := now.Sub(start)
			mu.Unlock()
			if lim.Idle > 0 && idle > lim.Idle {
				return finish("idle_timeout", "disconnected after "+lim.Idle.String()+" without input")
			}
			if lim.Max > 0 && elapsed > lim.Max {
				return finish("max_duration", "session reached the policy's maximum duration")
			}
		}
	}
}

// cleanCommandError turns a command-run error into a short line for the
// console. WinRM reports a command fault as an HTTP 500 carrying a SOAP
// envelope; showing that raw XML is useless, so collapse it to a plain message.
func cleanCommandError(err error) string {
	msg := strings.TrimSpace(err.Error())
	if i := strings.IndexByte(msg, '<'); i >= 0 { // strip any SOAP/XML body
		msg = strings.TrimSpace(msg[:i])
	}
	lower := strings.ToLower(msg)
	if msg == "" || strings.Contains(lower, "http 500") || strings.Contains(lower, "operationtimeout") {
		return "the command could not be run on the target"
	}
	return msg
}

func msgFor(reason string) string {
	switch reason {
	case "target_lost":
		return "connection to the target was lost"
	case "admin_terminated":
		return "session ended by an administrator"
	default:
		return ""
	}
}

// writerFunc adapts a function to io.Writer.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }
