// SPDX-License-Identifier: Apache-2.0

package apprelay

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// The SOCKS5 subset the browser needs (RFC 1928): no authentication, the
// CONNECT command, and the three address types. The relay sits alone with
// the browser on the session network, so no client needs telling apart; what
// it guards is where a connection may go.
const (
	socksVersion   = 5
	socksNoAuth    = 0
	socksNoMethods = 0xff
	socksConnect   = 1
	atypIPv4       = 1
	atypDomain     = 3
	atypIPv6       = 4

	replySucceeded       = 0
	replyNotAllowed      = 2
	replyHostUnreachable = 4
	replyRefused         = 5
	replyCmdUnsupported  = 7
	replyAtypUnsupported = 8
)

// serveSOCKS accepts on ln for s until ctx ends.
func (r *Relay) serveSOCKS(ctx context.Context, s *SOCKS, ln net.Listener) error {
	defer func() { _ = ln.Close() }()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	routes := make(map[string]string, len(s.Allow))
	for _, rt := range s.Allow {
		routes[net.JoinHostPort(normHost(rt.Host), strconv.Itoa(rt.Port))] = rt.To
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.socksConn(ctx, routes, c)
		}()
	}
}

// socksConn serves one client: the greeting and the request under a
// deadline, then, for an allowed destination, the pinned address dialled
// and the bytes copied both ways.
func (r *Relay) socksConn(ctx context.Context, routes map[string]string, c net.Conn) {
	defer func() { _ = c.Close() }()
	limit := r.HandshakeTimeout
	if limit <= 0 {
		limit = 10 * time.Second
	}
	_ = c.SetDeadline(time.Now().Add(limit))
	dest, ok := socksRequest(c)
	if !ok {
		return
	}
	to, allowed := routes[dest]
	if !allowed {
		// The browser's own background traffic (updates, sign-in) arrives
		// here all session long; a refusal is routine, not news.
		r.Log.Debug("apprelay socks refused", "dest", dest)
		socksReply(c, replyNotAllowed)
		return
	}
	b, err := r.Dial(ctx, to)
	if err != nil {
		r.Log.Warn("apprelay origin unreachable", "dest", dest, "to", to, "err", err)
		code := byte(replyHostUnreachable)
		if errors.Is(err, syscall.ECONNREFUSED) {
			code = replyRefused
		}
		socksReply(c, code)
		return
	}
	defer func() { _ = b.Close() }()
	if !socksReply(c, replySucceeded) {
		return
	}
	_ = c.SetDeadline(time.Time{})
	r.Log.Debug("apprelay socks connect", "dest", dest, "to", to)
	pipe(ctx, c, b)
}

// socksRequest reads the greeting and the request and returns the
// destination as host:port with the host as routes hold it. A greeting
// without "no authentication" is told so; a command other than CONNECT and
// an unknown address type are answered; anything else malformed is dropped.
func socksRequest(c net.Conn) (string, bool) {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != socksVersion {
		return "", false
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", false
	}
	method := byte(socksNoMethods)
	for _, m := range methods {
		if m == socksNoAuth {
			method = socksNoAuth
		}
	}
	if _, err := c.Write([]byte{socksVersion, method}); err != nil || method != socksNoAuth {
		return "", false
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != socksVersion {
		return "", false
	}
	var host string
	switch req[3] {
	case atypIPv4, atypIPv6:
		n := net.IPv4len
		if req[3] == atypIPv6 {
			n = net.IPv6len
		}
		ip := make(net.IP, n)
		if _, err := io.ReadFull(c, ip); err != nil {
			return "", false
		}
		host = ip.String()
	case atypDomain:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return "", false
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return "", false
		}
		host = string(name)
	default:
		socksReply(c, replyAtypUnsupported)
		return "", false
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return "", false
	}
	if req[1] != socksConnect {
		socksReply(c, replyCmdUnsupported)
		return "", false
	}
	return net.JoinHostPort(normHost(host), strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), true
}

// socksReply answers a request with code and an empty bound address, and
// says whether the write went through.
func socksReply(c net.Conn, code byte) bool {
	_, err := c.Write([]byte{socksVersion, code, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err == nil
}
