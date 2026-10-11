// SPDX-License-Identifier: Apache-2.0

package guac

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"time"

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

// Bridge relays instructions between guacd and the browser until either side
// ends. It returns the end reason for the access_sessions row.
func Bridge(ctx context.Context, log *slog.Logger, c *Conn, ws *websocket.Conn, rec Recorder, lim Limits) (string, error) {
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu     sync.Mutex
		reason = "user_exit"
		lastIn = time.Now()
		start  = time.Now()
		gdDone = make(chan struct{})
		wsDone = make(chan struct{})
		setEnd = func(r string) {
			mu.Lock()
			if reason == "user_exit" {
				reason = r
			}
			mu.Unlock()
		}
		current = func() string { mu.Lock(); defer mu.Unlock(); return reason }
		// coder/websocket permits only one concurrent writer. The guacd->browser
		// goroutine, the idle heartbeat and the final disconnect all write to the
		// browser, so every write is serialized through wsMu.
		wsMu    sync.Mutex
		wsWrite = func(wctx context.Context, raw string) error {
			wsMu.Lock()
			defer wsMu.Unlock()
			return ws.Write(wctx, websocket.MessageText, []byte(raw))
		}
	)

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
				if err := wsWrite(ctx, raw); err != nil {
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
			}
			if rec != nil {
				if err := rec.Write(raw); err != nil {
					log.Error("recording write failed; ending session", "err", err)
					setEnd("error")
					return
				}
			}
			if err := wsWrite(ctx, raw); err != nil {
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
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			raw := string(data)
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

	if lim.tick <= 0 {
		lim.tick = 5 * time.Second
	}
	ticker := time.NewTicker(lim.tick)
	defer ticker.Stop()
	finish := func(r, msg string) (string, error) {
		setEnd(r)
		r = current()
		wctx, wcancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer wcancel()
		if msg != "" {
			_ = wsWrite(wctx, ErrorInstruction(msg, 519))
		}
		_ = wsWrite(wctx, Encode("disconnect"))
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
			_ = c.Send("disconnect")
			cancel()
			return r, nil
		case <-gdDone:
			if r := current(); r != "user_exit" {
				return finish(r, "connection to the target was lost")
			}
			return finish("user_exit", "")
		case now := <-ticker.C:
			// Heartbeat: a static desktop produces no frames, and guacd may go
			// quiet for longer than the browser tunnel's 15s receiveTimeout, which
			// would drop the session as "target lost". A periodic nop keeps the
			// tunnel alive; the browser ignores its content.
			if err := wsWrite(ctx, Encode("nop")); err != nil {
				return current(), nil
			}
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
