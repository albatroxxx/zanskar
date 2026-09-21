// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/version"
)

// SyslogSink sends one RFC 5424 message per event over TCP or TLS with
// octet-counting framing (RFC 6587), carrying either a CEF record or the
// event as JSON. UDP is deliberately unsupported: audit delivery must not be
// silently lossy.
type SyslogSink struct {
	// Addr is tcp://host:port or tls://host:port.
	Addr string
	// Format is "cef" (default) or "json".
	Format string
	// CAFile pins the collector's CA for tls://. Empty uses system roots.
	CAFile string
	// Hostname appears in the syslog header. Default os.Hostname().
	Hostname string
	// Facility is the syslog facility (default 13, log audit).
	Facility int
	// DialTimeout bounds connection setup. Default 10 s.
	DialTimeout time.Duration

	mu   sync.Mutex
	conn net.Conn
}

// Name implements Sink.
func (s *SyslogSink) Name() string { return "syslog" }

// Send implements Sink. One TCP write per event; a failed write drops the
// connection so the next attempt reconnects and the batch is retried.
func (s *SyslogSink) Send(ctx context.Context, events []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureConn(ctx); err != nil {
		return err
	}
	for _, ev := range events {
		msg, err := s.format(ev)
		if err != nil {
			return err
		}
		frame := fmt.Sprintf("%d %s", len(msg), msg)
		if dl, ok := ctx.Deadline(); ok {
			_ = s.conn.SetWriteDeadline(dl)
		} else {
			_ = s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		}
		if _, err := s.conn.Write([]byte(frame)); err != nil {
			_ = s.conn.Close()
			s.conn = nil
			return fmt.Errorf("syslog write: %w", err)
		}
	}
	return nil
}

// Close closes the connection.
func (s *SyslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

func (s *SyslogSink) ensureConn(ctx context.Context) error {
	if s.conn != nil {
		return nil
	}
	u, err := url.Parse(s.Addr)
	if err != nil || u.Host == "" {
		return fmt.Errorf("syslog: bad address %q", s.Addr)
	}
	timeout := s.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := &net.Dialer{Timeout: timeout}
	switch u.Scheme {
	case "tcp":
		s.conn, err = d.DialContext(ctx, "tcp", u.Host)
	case "tls":
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		if s.CAFile != "" {
			pem, rerr := os.ReadFile(s.CAFile)
			if rerr != nil {
				return fmt.Errorf("syslog: read ca: %w", rerr)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return errors.New("syslog: ca file has no certificates")
			}
			cfg.RootCAs = pool
		}
		td := &tls.Dialer{NetDialer: d, Config: cfg}
		s.conn, err = td.DialContext(ctx, "tcp", u.Host)
	default:
		return fmt.Errorf("syslog: scheme must be tcp or tls, got %q", u.Scheme)
	}
	if err != nil {
		return fmt.Errorf("syslog dial: %w", err)
	}
	return nil
}

func (s *SyslogSink) format(ev Event) (string, error) {
	host := s.Hostname
	if host == "" {
		host, _ = os.Hostname()
		if host == "" {
			host = "-"
		}
	}
	facility := s.Facility
	if facility <= 0 {
		facility = 13
	}
	severity := 6 // informational
	if ev.Outcome == Failure {
		severity = 4 // warning
	}
	pri := facility*8 + severity
	ts := ev.Timestamp.UTC().Format(time.RFC3339Nano)
	var body string
	if strings.EqualFold(s.Format, "json") {
		b, err := json.Marshal(ev)
		if err != nil {
			return "", err
		}
		body = string(b)
	} else {
		body = CEF(ev)
	}
	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
	return fmt.Sprintf("<%d>1 %s %s zanskar - %s - %s", pri, ts, host, cefMsgID(ev), body), nil
}

func cefMsgID(ev Event) string {
	id := strings.ReplaceAll(ev.Action, ".", "-")
	if len(id) > 32 {
		id = id[:32]
	}
	if id == "" {
		return "-"
	}
	return id
}

// CEF renders an event as an ArcSight Common Event Format record. Header
// fields escape "|" and "\"; extension values escape "=" and "\" and fold
// newlines, per the CEF specification.
func CEF(ev Event) string {
	sev := "3"
	if ev.Outcome == Failure {
		sev = "6"
	}
	details := strings.TrimSpace(string(ev.Details))
	if details == "" {
		details = "{}"
	}
	ext := []string{
		"rt=" + fmt.Sprint(ev.Timestamp.UTC().UnixMilli()),
		"act=" + cefExt(ev.Action),
		"outcome=" + cefExt(string(ev.Outcome)),
		"suser=" + cefExt(ev.ActorUserID),
		"src=" + cefExt(ev.ActorIP),
		"cs1Label=objectType", "cs1=" + cefExt(ev.ObjectType),
		"cs2Label=objectId", "cs2=" + cefExt(ev.ObjectID),
		"cs3Label=hash", "cs3=" + cefExt(ev.Hash),
		"cs4Label=prevHash", "cs4=" + cefExt(ev.PrevHash),
		"externalId=" + fmt.Sprint(ev.ID),
		"msg=" + cefExt(details),
	}
	return fmt.Sprintf("CEF:0|Zanskar|Zanskar|%s|%s|%s|%s|%s",
		cefHeader(version.Version), cefHeader(ev.Action), cefHeader(ev.Action), sev, strings.Join(ext, " "))
}

func cefHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}

func cefExt(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, "\r\n", `\n`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return strings.ReplaceAll(s, "\r", `\n`)
}
