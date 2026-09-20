// SPDX-License-Identifier: Apache-2.0

package guac

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Params describe one connection guacd should open. Keys follow guacd's
// parameter names for the protocol (hostname, port, username, password,
// domain, security, ignore-cert, and so on).
type Params struct {
	Protocol string // rdp | vnc
	Args     map[string]string
	Width    int
	Height   int
	DPI      int
	// Audio, video and image mimetypes the browser client supports.
	Audio []string
	Video []string
	Image []string
	// Timezone is the client's zone for RDP time sync.
	Timezone string
}

// Conn is an established guacd connection after the handshake.
type Conn struct {
	net.Conn
	ID     string // connection id guacd assigned (from "ready")
	reader *Reader
}

// Dial connects to guacd and performs the handshake:
//
//	client: select <protocol>
//	guacd:  args <name>...
//	client: size, audio, video, image, timezone, connect <values in args order>
//	guacd:  ready <id>
//
// Parameter values are taken from p.Args by name; unknown names get "".
func Dial(ctx context.Context, addr string, p Params, timeout time.Duration) (*Conn, error) {
	if p.Protocol != "rdp" && p.Protocol != "vnc" {
		return nil, fmt.Errorf("guac: unsupported protocol %q", p.Protocol)
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
	if err := c.Send("select", p.Protocol); err != nil {
		return fail(err)
	}
	args, err := c.reader.Read()
	if err != nil {
		return fail(fmt.Errorf("guac: waiting for args: %w", err))
	}
	if args.Opcode != "args" {
		return fail(fmt.Errorf("guac: expected args, got %q", args.Opcode))
	}
	if p.Width <= 0 {
		p.Width = 1024
	}
	if p.Height <= 0 {
		p.Height = 768
	}
	if p.DPI <= 0 {
		p.DPI = 96
	}
	if err := c.Send("size", fmt.Sprint(p.Width), fmt.Sprint(p.Height), fmt.Sprint(p.DPI)); err != nil {
		return fail(err)
	}
	if err := c.Send("audio", p.Audio...); err != nil {
		return fail(err)
	}
	if err := c.Send("video", p.Video...); err != nil {
		return fail(err)
	}
	if err := c.Send("image", p.Image...); err != nil {
		return fail(err)
	}
	if p.Timezone != "" {
		if err := c.Send("timezone", p.Timezone); err != nil {
			return fail(err)
		}
	}
	values := make([]string, len(args.Args))
	for i, name := range args.Args {
		if i == 0 && strings.HasPrefix(name, "VERSION_") {
			// First arg advertises the protocol version; echo it back to
			// enable version-gated features such as the timezone instruction.
			values[i] = name
			continue
		}
		values[i] = p.Args[name]
	}
	if err := c.Send("connect", values...); err != nil {
		return fail(err)
	}
	ready, err := c.reader.Read()
	if err != nil {
		return fail(fmt.Errorf("guac: waiting for ready: %w", err))
	}
	if ready.Opcode == "error" {
		msg := "guacd refused the connection"
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

// Send writes one instruction.
func (c *Conn) Send(op string, args ...string) error {
	_, err := c.Write([]byte(Encode(op, args...)))
	return err
}

// ReadRaw returns the next raw instruction from guacd.
func (c *Conn) ReadRaw() (string, error) { return c.reader.ReadRaw() }
