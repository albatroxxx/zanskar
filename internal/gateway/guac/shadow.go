// SPDX-License-Identifier: Apache-2.0

package guac

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// Join attaches a second, read-only client to an existing guacd connection.
// guacd accepts the connection id from an earlier "ready" instruction in
// place of a protocol name in "select"; with the "read-only" parameter set
// the joined client receives the display but its input is discarded. This is
// how an auditor shadows a live desktop session.
func Join(ctx context.Context, addr, connectionID string, width, height int, timeout time.Duration) (*Conn, error) {
	if !strings.HasPrefix(connectionID, "$") {
		return nil, errors.New("guac: not a guacd connection id")
	}
	d := net.Dialer{Timeout: timeout}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("guac: dial guacd: %w", err)
	}
	if err := nc.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = nc.Close()
		return nil, err
	}
	c := &Conn{Conn: nc, reader: NewReader(nc)}
	fail := func(err error) (*Conn, error) {
		_ = nc.Close()
		return nil, err
	}
	if err := c.Send("select", connectionID); err != nil {
		return fail(err)
	}
	args, err := c.reader.Read()
	if err != nil {
		return fail(fmt.Errorf("guac: waiting for args: %w", err))
	}
	if args.Opcode != "args" {
		return fail(fmt.Errorf("guac: expected args, got %q", args.Opcode))
	}
	if width <= 0 {
		width = 1024
	}
	if height <= 0 {
		height = 768
	}
	if err := c.Send("size", fmt.Sprint(width), fmt.Sprint(height), "96"); err != nil {
		return fail(err)
	}
	for _, op := range []string{"audio", "video"} {
		if err := c.Send(op); err != nil {
			return fail(err)
		}
	}
	if err := c.Send("image", "image/png", "image/jpeg", "image/webp"); err != nil {
		return fail(err)
	}
	values := make([]string, len(args.Args))
	for i, name := range args.Args {
		switch {
		case i == 0 && strings.HasPrefix(name, "VERSION_"):
			values[i] = name
		case name == "read-only":
			values[i] = "true"
		}
	}
	if err := c.Send("connect", values...); err != nil {
		return fail(err)
	}
	ready, err := c.reader.Read()
	if err != nil {
		return fail(fmt.Errorf("guac: waiting for ready: %w", err))
	}
	if ready.Opcode == "error" {
		msg := "guacd refused the join"
		if len(ready.Args) > 0 {
			msg = ready.Args[0]
		}
		return fail(fmt.Errorf("guac: %s", msg))
	}
	if ready.Opcode != "ready" || len(ready.Args) == 0 {
		return fail(fmt.Errorf("guac: expected ready, got %q", ready.Opcode))
	}
	c.ID = ready.Args[0]
	_ = nc.SetDeadline(time.Time{})
	return c, nil
}

// Relay streams guacd's instructions to a watcher's browser. Browser
// instructions are dropped except "nop" and "sync", which guacd needs for
// keepalive and frame acknowledgement. It returns when either side ends.
func Relay(ctx context.Context, c *Conn, ws *websocket.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 2)
	go func() {
		for {
			raw, err := c.ReadRaw()
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				errCh <- err
				return
			}
			if err := ws.Write(ctx, websocket.MessageText, []byte(raw)); err != nil {
				errCh <- nil
				return
			}
			if op := Opcode(raw); op == "disconnect" || op == "error" {
				errCh <- nil
				return
			}
		}
	}()
	go func() {
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				errCh <- nil
				return
			}
			switch Opcode(string(data)) {
			case "nop", "sync":
				if _, err := c.Write(data); err != nil {
					errCh <- nil
					return
				}
			}
		}
	}()
	err := <-errCh
	cancel()
	_ = c.Send("disconnect")
	return err
}
