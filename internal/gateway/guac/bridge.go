// SPDX-License-Identifier: Apache-2.0

package guac

import (
	"context"
	"errors"
	"io"
	"log/slog"
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
	)

	// guacd -> browser
	go func() {
		defer close(gdDone)
		for {
			raw, err := c.ReadRaw()
			if err != nil {
				if !errors.Is(err, io.EOF) && ctx.Err() == nil {
					setEnd("target_lost")
				}
				return
			}
			op := Opcode(raw)
			switch op {
			case "nop":
				continue
			case "clipboard":
				if !lim.AllowClipboard {
					continue
				}
			case "file", "pipe", "filesystem", "body", "undefine":
				if !lim.AllowFileTransfer {
					continue
				}
			case "error":
				setEnd("target_lost")
			}
			if rec != nil {
				if err := rec.Write(raw); err != nil {
					log.Error("recording write failed; ending session", "err", err)
					setEnd("error")
					return
				}
			}
			if err := ws.Write(ctx, websocket.MessageText, []byte(raw)); err != nil {
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
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			raw := string(data)
			op := Opcode(raw)
			switch op {
			case "nop", "sync":
				// keepalives and frame acks do not count as user activity
			case "clipboard":
				if !lim.AllowClipboard {
					continue
				}
				touch(&mu, &lastIn)
			case "file", "pipe", "get", "put":
				if !lim.AllowFileTransfer {
					continue
				}
				touch(&mu, &lastIn)
			case "mouse", "key":
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
			_ = ws.Write(wctx, websocket.MessageText, []byte(ErrorInstruction(msg, 519)))
		}
		_ = ws.Write(wctx, websocket.MessageText, []byte(Encode("disconnect")))
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
