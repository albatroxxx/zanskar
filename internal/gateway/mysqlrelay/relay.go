// SPDX-License-Identifier: Apache-2.0

// Package mysqlrelay is the credential-holding hop for MySQL and MariaDB
// sessions (ADR 0017). It runs as the per-session sidecar (`zanskar
// dbproxy`) beside the client container: the client signs in to it as the
// session user with no password, it signs in upstream with the vaulted
// credential, and from then on it relays the wire protocol between the two.
// The client container never holds the credential, and the relay refuses
// re-authentication so it cannot be used to guess one either.
//
// Both handshakes are done by go-mysql: the upstream one with its proven
// mysql_native_password, caching_sha2_password, sha256_password and
// MariaDB ed25519 implementations, the client-facing one by its server
// half. Nothing here touches a password hash. Once both sides are past
// authentication the relay copies bytes; for that to be sound the two
// connections must agree on every capability flag that changes how packets
// are framed, which the relay negotiates deliberately and then verifies.
package mysqlrelay

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

// TLSMode says how the upstream connection is protected.
type TLSMode string

// TLS modes, named after libpq's since operators know those.
const (
	// TLSPrefer encrypts when the server offers TLS and falls back to plain
	// otherwise; the certificate is not verified. It mirrors the pgbouncer
	// sidecar's server_tls_sslmode=prefer. Verification arrives with the
	// target's TLS settings.
	TLSPrefer TLSMode = "prefer"
	// TLSRequire refuses a server that does not offer TLS.
	TLSRequire TLSMode = "require"
	// TLSDisable never negotiates TLS.
	TLSDisable TLSMode = "disable"
)

// Upstream is the database the relay signs in to.
type Upstream struct {
	Addr     string  `json:"addr"` // host:port
	User     string  `json:"user"`
	Password string  `json:"password"`
	Database string  `json:"database,omitempty"`
	TLS      TLSMode `json:"tls,omitempty"` // default prefer
}

// Config is what the sidecar is started with: one JSON document in the
// ZANSKAR_DBPROXY environment variable, so the password is never in argv.
type Config struct {
	// Listen is the client-facing address; default :3306.
	Listen string `json:"listen,omitempty"`
	// User is the only username the client may sign in as, with no
	// password; empty means the upstream user.
	User     string   `json:"user,omitempty"`
	Upstream Upstream `json:"upstream"`
	// DialTimeout bounds the upstream connect and handshake; default 15s.
	DialTimeout time.Duration `json:"-"`
}

// Parse decodes and validates a Config from its JSON form.
func Parse(raw []byte) (Config, error) {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("dbproxy config: %w", err)
	}
	return c, c.Validate()
}

// Validate fills defaults and refuses an incomplete configuration.
func (c *Config) Validate() error {
	if c.Listen == "" {
		c.Listen = ":3306"
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 15 * time.Second
	}
	if c.Upstream.TLS == "" {
		c.Upstream.TLS = TLSPrefer
	}
	switch c.Upstream.TLS {
	case TLSPrefer, TLSRequire, TLSDisable:
	default:
		return fmt.Errorf("dbproxy config: tls must be prefer, require or disable")
	}
	if _, _, err := net.SplitHostPort(c.Upstream.Addr); err != nil {
		return fmt.Errorf("dbproxy config: upstream addr must be host:port")
	}
	if c.Upstream.User == "" {
		return errors.New("dbproxy config: upstream user is required")
	}
	if c.User == "" {
		c.User = c.Upstream.User
	}
	return nil
}

// Relay accepts client connections and bridges each to its own upstream
// connection.
type Relay struct {
	Config
	Log *slog.Logger
}

// Serve accepts on ln until ctx ends. Every connection gets its own
// upstream connection, so the CLI's reconnect (\r) works.
func (r *Relay) Serve(ctx context.Context, ln net.Listener) error {
	if r.Log == nil {
		r.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.handle(ctx, conn)
		}()
	}
}

// framingMask lists the capability flags that change how packets after
// authentication are laid out. The two sides of the relay must hold the
// same value for every one of them or a result set is misread.
const framingMask = mysql.CLIENT_PROTOCOL_41 | mysql.CLIENT_LONG_FLAG | mysql.CLIENT_TRANSACTIONS |
	mysql.CLIENT_DEPRECATE_EOF | mysql.CLIENT_QUERY_ATTRIBUTES | mysql.CLIENT_OPTIONAL_RESULTSET_METADATA |
	mysql.CLIENT_SESSION_TRACK | mysql.CLIENT_MULTI_RESULTS | mysql.CLIENT_PS_MULTI_RESULTS |
	mysql.CLIENT_COMPRESS | mysql.CLIENT_ZSTD_COMPRESSION_ALGORITHM | mysql.CLIENT_LOCAL_FILES

// requested are the framing flags the relay asks the upstream for. The
// client-facing server (go-mysql) advertises exactly these and none of the
// others in framingMask, so a conforming client ends up with a subset.
const requested = mysql.CLIENT_PROTOCOL_41 | mysql.CLIENT_LONG_FLAG | mysql.CLIENT_TRANSACTIONS |
	mysql.CLIENT_SESSION_TRACK | mysql.CLIENT_MULTI_RESULTS | mysql.CLIENT_PS_MULTI_RESULTS

func (r *Relay) handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	front := newPaced(conn)

	// Upstream first, so a database that is down or refuses the credential
	// turns into a clean error in the client's own sign-in rather than a
	// hang or a dropped socket.
	up, upErr := r.dial(ctx)
	version := "8.0.0-zanskar"
	var upCaps uint32
	if upErr == nil {
		version = up.GetServerVersion()
		upCaps = negotiated(up)
		defer func() { _ = up.Close() }()
	} else {
		r.Log.Warn("upstream connect failed", "err", upErr)
	}
	auth := &trustAuth{user: r.User, upstreamErr: upErr, upCaps: upCaps}
	srv := server.NewServer(version, mysql.DEFAULT_COLLATION_ID, mysql.AUTH_NATIVE_PASSWORD, nil, nil)
	fc, err := srv.NewCustomizedConn(front, auth, quietHandler{})
	if err != nil {
		r.Log.Warn("client sign-in refused", "err", err)
		return
	}
	defer fc.Close()
	if upErr != nil {
		return
	}
	r.Log.Info("session open", "client", conn.RemoteAddr().String(), "server_version", version)
	// Both handshakes are complete and, thanks to the paced reader, no byte
	// past the last handshake packet sits in a buffer: relay the rest raw.
	upRaw := up.Conn.Conn
	errc := make(chan error, 2)
	go func() { errc <- relayCommands(front, upRaw) }()
	go func() {
		_, err := io.Copy(front, upRaw)
		errc <- err
	}()
	select {
	case <-ctx.Done():
	case <-errc:
	}
	_ = front.Close()
	_ = upRaw.Close()
	<-errc
}

// dial connects upstream in the configured TLS mode. In prefer mode a
// failure that is not the server's own refusal is retried without TLS,
// which is what a server that does not offer TLS looks like from here.
func (r *Relay) dial(ctx context.Context) (*client.Conn, error) {
	switch r.Upstream.TLS {
	case TLSDisable:
		return r.connect(ctx, false)
	case TLSRequire:
		return r.connect(ctx, true)
	default:
		c, err := r.connect(ctx, true)
		var my *mysql.MyError
		if err != nil && !errors.As(err, &my) {
			r.Log.Info("upstream did not complete TLS; retrying in plain", "err", err)
			c, err = r.connect(ctx, false)
		}
		return c, err
	}
}

func (r *Relay) connect(ctx context.Context, useTLS bool) (*client.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, r.DialTimeout)
	defer cancel()
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if useTLS {
			// go-mysql wraps the socket in TLS itself; pacing TLS records
			// would break them. The post-handshake read then comes from
			// the tls.Conn, whose own buffering is transparent.
			return c, nil
		}
		return newPaced(c), nil
	}
	opt := func(c *client.Conn) error {
		c.ReadTimeout, c.WriteTimeout = r.DialTimeout, r.DialTimeout
		// Classic framing on the upstream leg: what the client-facing
		// server offers, nothing it does not.
		c.UnsetCapability(mysql.CLIENT_DEPRECATE_EOF)
		c.UnsetCapability(mysql.CLIENT_QUERY_ATTRIBUTES)
		for _, f := range []uint32{mysql.CLIENT_MULTI_RESULTS, mysql.CLIENT_PS_MULTI_RESULTS, mysql.CLIENT_SESSION_TRACK} {
			if err := c.SetCapability(f); err != nil {
				return err
			}
		}
		if useTLS {
			c.SetTLSConfig(unverifiedTLS())
		}
		return nil
	}
	up, err := client.ConnectWithDialer(ctx, "tcp", r.Upstream.Addr, r.Upstream.User, r.Upstream.Password, r.Upstream.Database, dialer, opt)
	if err != nil {
		return nil, err
	}
	// One round trip after sign-in: on the TLS path the library's reader is
	// buffered, and a server that pushed anything after its OK would show
	// up here as a malformed reply rather than as silent corruption later.
	if err := up.Ping(); err != nil {
		_ = up.Close()
		return nil, fmt.Errorf("upstream ping after sign-in: %w", err)
	}
	return up, nil
}

// unverifiedTLS encrypts the upstream connection without verifying the
// server's certificate: the pgbouncer sidecar's server_tls_sslmode=prefer
// for MySQL, and what the target's prefer and require modes mean. It
// defeats a passive listener, not an on-path one; verify-full is the mode
// for that, and arrives with the target's TLS settings.
func unverifiedTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // #nosec G402 -- by the target's TLS mode; see the doc comment
}

// negotiated computes the framing flags in force upstream: what the relay
// asked for, of what the server offered. go-mysql reports the server's
// offer by name only.
func negotiated(up *client.Conn) uint32 {
	byName := map[string]uint32{}
	for f, n := range mysql.CapNames {
		byName[n] = f
	}
	var offered uint32
	for _, n := range strings.Split(up.CapabilityString(), "|") {
		offered |= byName[n]
	}
	return requested & offered
}

// trustAuth is the client-facing authentication: the session user, no
// password, nobody else. It also carries the upstream outcome into the
// handshake so the client sees a proper error packet.
type trustAuth struct {
	user        string
	upstreamErr error
	upCaps      uint32
}

func (a *trustAuth) GetCredential(username string) (server.Credential, bool, error) {
	if a.upstreamErr != nil {
		var my *mysql.MyError
		if errors.As(a.upstreamErr, &my) {
			// The database's own refusal, for example a password the vault
			// holds that the server no longer accepts.
			return server.Credential{}, false, my
		}
		// Anything else names the upstream host or a network detail the
		// client container must not learn; the sidecar log has it.
		return server.Credential{}, false, mysql.NewError(mysql.ER_UNKNOWN_ERROR, "the database did not accept the connection; the gateway log has the reason")
	}
	if username != a.user {
		return server.Credential{}, false, mysql.NewError(mysql.ER_ACCESS_DENIED_ERROR, "this session signs in as '"+a.user+"' only")
	}
	return server.Credential{Passwords: []string{""}, AuthPluginName: mysql.AUTH_NATIVE_PASSWORD}, true, nil
}

func (a *trustAuth) OnAuthSuccess(c *server.Conn) error {
	if diff := framingMismatch(c.Capability(), a.upCaps); diff != 0 {
		return mysql.NewError(mysql.ER_NOT_SUPPORTED_YET, fmt.Sprintf("client and server disagree on protocol capabilities (%s)", capNames(diff)))
	}
	return nil
}

// framingMismatch reports the framing flags on which the client-facing and
// the upstream connection would disagree. A client's flags are taken as
// sent, but what it can actually use is limited to what the server offered
// (libmysqlclient echoes bits like DEPRECATE_EOF regardless and then frames
// by the server's offer), so the effective client set is the intersection
// with the relay's offer.
func framingMismatch(clientFlags, upstream uint32) uint32 {
	return ((clientFlags & requested) ^ upstream) & framingMask
}

func (a *trustAuth) OnAuthFailure(*server.Conn, error) {}

// quietHandler is the command handler the relay never uses (commands are
// relayed raw); go-mysql's EmptyHandler prints USE to stdout, which would
// end up in the sidecar's log.
type quietHandler struct{ server.EmptyHandler }

func (quietHandler) UseDB(string) error { return nil }

func capNames(flags uint32) string {
	var names []string
	for f, n := range mysql.CapNames {
		if flags&f != 0 {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return fmt.Sprintf("%#x", flags)
	}
	return strings.Join(names, ", ")
}

// relayCommands copies client packets to the upstream, looking at the
// first byte of each command. COM_CHANGE_USER is answered with an error
// instead of forwarded: it is the one command that would let a program in
// the client container try credentials against the database.
func relayCommands(src io.Reader, dst io.Writer) error {
	var hdr [4]byte
	buf := make([]byte, 0, 64<<10)
	for {
		if _, err := io.ReadFull(src, hdr[:]); err != nil {
			return err
		}
		n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		if cap(buf) < n {
			buf = make([]byte, 0, n)
		}
		payload := buf[:n]
		if _, err := io.ReadFull(src, payload); err != nil {
			return err
		}
		if hdr[3] == 0 && n > 0 && payload[0] == mysql.COM_CHANGE_USER {
			if w, ok := src.(io.Writer); ok {
				if err := writeErr(w, 1, mysql.ER_NOT_SUPPORTED_YET, "re-authentication is not available through the gateway"); err != nil {
					return err
				}
			}
			continue
		}
		if _, err := dst.Write(hdr[:]); err != nil {
			return err
		}
		if _, err := dst.Write(payload); err != nil {
			return err
		}
	}
}

// writeErr sends an ERR packet with the given sequence number. The message
// is a short fixed string, so the 3-byte length and 2-byte code cannot
// overflow.
func writeErr(w io.Writer, seq byte, code uint16, msg string) error {
	pkt := make([]byte, 4, 13+len(msg))
	pkt = append(pkt, mysql.ERR_HEADER)
	pkt = binary.LittleEndian.AppendUint16(pkt, code)
	pkt = append(pkt, '#')
	pkt = append(pkt, "HY000"...)
	pkt = append(pkt, msg...)
	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], uint32(len(pkt)-4)) // #nosec G115 -- bounded by the fixed message
	copy(pkt[:3], length[:3])
	pkt[3] = seq
	_, err := w.Write(pkt)
	return err
}

// paced is a net.Conn whose Read never returns bytes from more than one
// MySQL packet. go-mysql reads through a bufio.Reader that fills with one
// Read of up to its whole buffer, so without this it could hold the start
// of the packet after the handshake, which the relay's raw copy would then
// never see. With it, the buffer is empty at every packet boundary.
type paced struct {
	net.Conn
	hdr     [4]byte
	hdrLeft int // header bytes not yet handed out
	payLeft int // payload bytes not yet handed out
}

func newPaced(c net.Conn) *paced { return &paced{Conn: c} }

func (p *paced) Read(b []byte) (int, error) {
	if p.hdrLeft == 0 && p.payLeft == 0 {
		if _, err := io.ReadFull(p.Conn, p.hdr[:]); err != nil {
			return 0, err
		}
		p.hdrLeft = 4
		p.payLeft = int(p.hdr[0]) | int(p.hdr[1])<<8 | int(p.hdr[2])<<16
	}
	n := 0
	if p.hdrLeft > 0 {
		n = copy(b, p.hdr[4-p.hdrLeft:])
		p.hdrLeft -= n
		if p.hdrLeft > 0 || len(b) == n {
			return n, nil
		}
	}
	if p.payLeft > 0 {
		want := len(b) - n
		if want > p.payLeft {
			want = p.payLeft
		}
		m, err := p.Conn.Read(b[n : n+want])
		p.payLeft -= m
		n += m
		if err != nil && m == 0 {
			return n, err
		}
	}
	return n, nil
}
