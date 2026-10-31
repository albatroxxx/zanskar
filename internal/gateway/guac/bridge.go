// SPDX-License-Identifier: Apache-2.0

package guac

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/gateway"
)

// Recorder receives the server-to-client instruction stream. Replaying it
// through guacamole-common-js's SessionRecording reproduces the desktop.
type Recorder interface {
	Write(raw string) error
}

// Limits mirror the SSH bridge.
type Limits struct {
	Idle time.Duration
	Max  time.Duration
	// AllowClipboard controls whether clipboard instructions pass in either
	// direction. Without it, "clipboard" and its blob streams are dropped.
	AllowClipboard bool
	// AllowFileTransfer controls "file" and "pipe" streams and the drive
	// redirection object protocol ("filesystem", "body", "get", "put").
	AllowFileTransfer bool
	tick              time.Duration
}

// allows reports whether the policy lets an opcode through. The same table
// serves both directions: an opcode that only one side ever sends is simply
// never seen from the other.
func (lim Limits) allows(op string) bool {
	switch op {
	case "clipboard":
		return lim.AllowClipboard
	case "file", "pipe", "filesystem", "body", "undefine", "get", "put":
		return lim.AllowFileTransfer
	}
	return true
}

// Stream-opening opcodes per direction, with the argument that carries the
// stream index. Most name the stream first; "body" and "put" name the object
// first and the stream second.
var (
	serverOpens = map[string]int{"audio": 0, "argv": 0, "clipboard": 0, "file": 0, "img": 0, "pipe": 0, "video": 0, "body": 1}
	clientOpens = map[string]int{"audio": 0, "argv": 0, "clipboard": 0, "file": 0, "pipe": 0, "put": 1}
)

// statusClientForbidden is the Guacamole status the bridge answers a refused
// stream with (0x0303, "permission was denied to perform the operation").
const statusClientForbidden = 0x0303

// Statuses of the "error" instruction that tells the browser why its session
// ended. The console reads 519 (upstream not found) as a lost target and, on
// an autoscaling group, offers to switch to another instance, so only a lost
// target may carry it; an end the gateway decided (an administrator, a
// policy, a restart, a limit, a refusal before the session began) is 523,
// session closed.
const (
	StatusUpstreamNotFound = 0x0207
	StatusSessionClosed    = 0x020B
)

// endStatus is the status the end of a session with this reason carries.
func endStatus(reason string) int {
	if reason == "target_lost" {
		return StatusUpstreamNotFound
	}
	return StatusSessionClosed
}

// streamFilter applies the policy to one direction of the relay. Guacamole
// moves clipboard text and files as streams: an opening instruction
// ("clipboard", "file", "body", "put", ...) names a stream index, and the
// data follows as "blob" instructions and an "end" for that index. Dropping
// the opening instruction alone would leave the data flowing, so the filter
// remembers the index of every stream it refused and drops its blobs and end
// as well. The two sides number their streams independently, so each
// direction has its own filter, owned by the goroutine relaying that way.
type streamFilter struct {
	opens   map[string]int
	blocked map[int]struct{}
}

func newStreamFilter(opens map[string]int) *streamFilter {
	return &streamFilter{opens: opens, blocked: map[int]struct{}{}}
}

// check decides whether a raw instruction may be relayed. refused is the
// index of a stream whose opening instruction was just dropped by policy, or
// -1; the caller decides what the other side needs to hear about it.
func (f *streamFilter) check(raw, op string, lim Limits) (pass bool, refused int) {
	refused = -1
	if op == "blob" || op == "end" {
		idx, ok := streamIndex(raw, 0)
		if !ok {
			// Not an index guacd could have allocated or would accept: guacd
			// parses indexes with atoi, so "00" would land on stream 0 while the
			// bridge saw a different stream. Nobody legitimate sends this.
			return false, refused
		}
		if _, blocked := f.blocked[idx]; !blocked {
			return true, refused
		}
		if op == "end" {
			delete(f.blocked, idx)
		}
		return false, refused
	}
	arg, opens := f.opens[op]
	if !opens {
		return lim.allows(op), refused
	}
	idx, ok := streamIndex(raw, arg)
	if !ok {
		return false, refused
	}
	// The index is in use again, so whatever it referred to before is over:
	// guacd reuses an index it freed without an "end" when a stream was
	// refused, and the next user of that index may well be the display.
	delete(f.blocked, idx)
	if lim.allows(op) {
		return true, refused
	}
	f.blocked[idx] = struct{}{}
	return false, idx
}

// UpstreamError is the "error" instruction guacd ended a session with: its
// words and its Guacamole status. "Upstream error." with 0x0203, for one, is
// an RDP server that disconnected with a reason code guacd has no words for;
// a dropped connection is "Connection closed." with 0x0208.
type UpstreamError struct {
	Message string
	Status  int
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("guacd: %s (status 0x%04X)", e.Message, e.Status)
}

// maxUpstreamMessage bounds the words kept from guacd's "error" instruction:
// they go into the log and the audit trail, and guacd's own are a line long.
const maxUpstreamMessage = 200

// upstreamError reads guacd's "error" instruction: the message, then the
// status as a decimal number.
func upstreamError(raw string) *UpstreamError {
	in, err := Parse(raw)
	if err != nil || len(in.Args) == 0 {
		return &UpstreamError{Message: "unreadable error instruction"}
	}
	msg := strings.ToValidUTF8(in.Args[0], "")
	if len(msg) > maxUpstreamMessage {
		msg = msg[:maxUpstreamMessage]
		for !utf8.ValidString(msg) {
			msg = msg[:len(msg)-1]
		}
	}
	e := &UpstreamError{Message: msg}
	if len(in.Args) > 1 {
		e.Status, _ = strconv.Atoi(in.Args[1])
	}
	return e
}

// Bridge relays instructions between guacd and the browser until either side
// ends. It returns the end reason for the access_sessions row and, when guacd
// ended the session with an "error" instruction, an *UpstreamError carrying
// what guacd said. Once the browser has been told why the session ended,
// Bridge closes ws normally (gateway.CloseAfterEnd).
func Bridge(ctx context.Context, log *slog.Logger, c *Conn, ws *websocket.Conn, rec Recorder, lim Limits) (_ string, err error) {
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The browser is read and written under a context of its own, which the
	// session's cancellation does not reach. coder/websocket drops the
	// connection when the context of a read or write in progress is
	// cancelled, so reading under ctx let an administrator, a restart, a
	// policy change or the autoscaling sync tear the socket down before the
	// browser heard why. wsCancel ends it: through CloseAfterEnd once the
	// browser has been told, or at once when the browser has gone.
	wsCtx, wsCancel := context.WithCancel(context.WithoutCancel(ctx))
	var (
		mu       sync.Mutex
		reason   = "user_exit"
		upstream *UpstreamError // guacd's "error" instruction, when it sent one
		lastIn   = time.Now()
		start    = time.Now()
		gdDone   = make(chan struct{})
		wsDone   = make(chan struct{})
		setEnd   = func(r string) {
			mu.Lock()
			if reason == "user_exit" {
				reason = r
			}
			mu.Unlock()
		}
		current = func() string { mu.Lock(); defer mu.Unlock(); return reason }
		// The guacd->browser goroutine, the heartbeat and the final
		// disconnect all write to the browser. coder/websocket takes the
		// connection's write lock for each whole message and waits for it
		// under the write's context, so the writers go one message at a time
		// and the final messages' deadline also bounds their wait behind a
		// write to a browser that has stopped reading. A lock of the bridge's
		// own would not honour that deadline.
		wsWrite = func(wctx context.Context, raw string) error {
			return ws.Write(wctx, websocket.MessageText, []byte(raw))
		}
	)
	// Whichever way the session then ends, what guacd said goes back with it.
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		if err == nil && upstream != nil {
			err = upstream
		}
	}()

	// guacd -> browser
	go func() {
		defer close(gdDone)
		filter := newStreamFilter(serverOpens)
		for {
			raw, err := c.ReadRaw()
			if err != nil {
				if !errors.Is(err, io.EOF) && ctx.Err() == nil {
					setEnd("target_lost")
				}
				return
			}
			op := Opcode(raw)
			if op == "nop" {
				// guacd's keepalive. Forward it so the browser's tunnel
				// receiveTimeout (15s without any server message) does not fire on
				// an idle, unchanging desktop, but do not record it.
				if err := wsWrite(wsCtx, raw); err != nil {
					return
				}
				continue
			}
			pass, refused := filter.check(raw, op, lim)
			if refused >= 0 {
				// guacd waits for the browser to acknowledge a "file" or "body"
				// stream before it sends the first blob, and the browser never saw
				// this one. Decline it on the browser's behalf, as a stock client
				// does for a stream type it has no handler for, so guacd closes the
				// file and frees the stream instead of holding both until the
				// session ends. A "clipboard" stream is sent in one go and freed
				// before the answer arrives; guacd ignores the late ack.
				if err := c.Send("ack", strconv.Itoa(refused), "blocked by policy", strconv.Itoa(statusClientForbidden)); err != nil {
					setEnd("target_lost")
					return
				}
			}
			if !pass {
				// Dropped by policy: neither the browser nor the recording sees it.
				continue
			}
			if op == "error" {
				setEnd("target_lost")
				e := upstreamError(raw)
				mu.Lock()
				upstream = e
				mu.Unlock()
			}
			if rec != nil {
				if err := rec.Write(raw); err != nil {
					log.Error("recording write failed; ending session", "err", err)
					setEnd("error")
					return
				}
			}
			if err := wsWrite(wsCtx, raw); err != nil {
				return
			}
			if op == "disconnect" || op == "error" {
				return
			}
		}
	}()

	// browser -> guacd
	go func() {
		defer close(wsDone)
		filter := newStreamFilter(clientOpens)
		malformed := 0
		for {
			_, data, err := ws.Read(wsCtx)
			if err != nil {
				return
			}
			raw := string(data)
			// One message is one instruction. guacd parses what it is sent
			// as a stream, so a message carrying several instructions would
			// have only its first one judged by the policy below and the
			// rest relayed unseen; a stock client never sends such a thing,
			// and a message that is not exactly one instruction is dropped.
			if _, err := Parse(raw); err != nil {
				if malformed++; malformed == 1 {
					log.Warn("desktop client sent a malformed or compound instruction; dropped", "bytes", len(raw))
				}
				continue
			}
			op := Opcode(raw)
			if pass, _ := filter.check(raw, op, lim); !pass {
				continue
			}
			switch op {
			case "nop", "sync":
				// keepalives and frame acks do not count as user activity
			case "clipboard", "file", "pipe", "get", "put", "mouse", "key":
				touch(&mu, &lastIn)
			}
			if _, err := c.Write([]byte(raw)); err != nil {
				setEnd("target_lost")
				return
			}
		}
	}()

	// A local, not lim.tick: the relay goroutines above copy lim, so writing
	// to it now would race with them.
	tick := lim.tick
	if tick <= 0 {
		tick = 5 * time.Second
	}
	// Heartbeat: a static desktop produces no frames, and guacd may go quiet
	// for longer than the browser tunnel's 15s receiveTimeout, which would
	// drop the session as "target lost". A periodic nop keeps the tunnel
	// alive; the browser ignores its content. It runs apart from the loop
	// below, so a browser that has stopped reading can hold up a nop but
	// never the end of the session.
	go func() {
		beat := time.NewTicker(tick)
		defer beat.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-beat.C:
				if wsWrite(wsCtx, Encode("nop")) != nil {
					return
				}
			}
		}
	}()
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	finish := func(r, msg string) (string, error) {
		setEnd(r)
		r = current()
		wctx, wcancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer wcancel()
		if msg != "" {
			_ = wsWrite(wctx, ErrorInstruction(msg, endStatus(r)))
		}
		_ = wsWrite(wctx, Encode("disconnect"))
		gateway.CloseAfterEnd(ws, r, wsCancel)
		_ = c.Send("disconnect")
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
		case <-wsDone:
			r := current()
			wsCancel()
			_ = c.Send("disconnect")
			cancel()
			return r, nil
		case <-gdDone:
			if r := current(); r != "user_exit" {
				return finish(r, "connection to the target was lost")
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

func touch(mu *sync.Mutex, t *time.Time) {
	mu.Lock()
	*t = time.Now()
	mu.Unlock()
}
