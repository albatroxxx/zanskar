// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
)

// sendTimeout bounds one delivery, webhook or email.
const sendTimeout = 15 * time.Second

// refusedIP is an address no notification is sent to: loopback, link-local
// (a cloud's metadata service lives there), unspecified, multicast (ADR
// 0039). Private networks are allowed: a relay on the LAN is common.
func refusedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast()
}

// guardedDialer refuses, at dial time, an address refusedIP names, so a name
// that resolves there now is refused whatever it resolved to when saved.
func guardedDialer(allowLoopback bool) *net.Dialer {
	return &net.Dialer{Timeout: sendTimeout, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("notify: dialled %q, not an address", host)
		}
		if allowLoopback && ip.IsLoopback() {
			return nil
		}
		if refusedIP(ip) {
			return fmt.Errorf("notify: %s is not an address notifications go to", ip)
		}
		return nil
	}}
}

// CheckWebhookURL says whether a webhook URL may be saved: https, a host,
// no credentials in it, and not an address refusedIP names.
func CheckWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("the webhook address must be an https:// URL without a user or password in it")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && refusedIP(ip) {
		return errors.New("the webhook address is a loopback, link-local or unspecified address, which notifications are not sent to")
	}
	return nil
}

// Sender delivers one message on one channel.
type Sender struct {
	// Transport, when set, carries webhook requests (tests); its dials are
	// not guarded. Nil uses a guarded one.
	Transport http.RoundTripper
	// AllowLoopback lets tests reach a server on 127.0.0.1.
	AllowLoopback bool
}

// Send delivers m on c.
func (s *Sender) Send(ctx context.Context, c *Channel, m Message) error {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	switch c.Kind {
	case KindWebhook:
		return s.webhook(ctx, c, m)
	case KindEmail:
		return s.email(ctx, c, m)
	}
	return fmt.Errorf("notify: unknown channel kind %q", c.Kind)
}

// webhook POSTs the message as JSON whose text is the sentence (what Slack's
// and Mattermost's incoming webhooks show) beside a zanskar object, signed
// as the SIEM export signs (audit.Sign).
func (s *Sender) webhook(ctx context.Context, c *Channel, m Message) error {
	if c.secret.WebhookURL == "" {
		return errors.New("the webhook has no address stored")
	}
	if err := CheckWebhookURL(c.secret.WebhookURL); err != nil {
		return err
	}
	text := m.Text
	if m.Link != "" {
		text += " " + m.Link
	}
	body, err := json.Marshal(map[string]any{
		"text":    text,
		"zanskar": map[string]any{"kind": m.Kind, "event_id": m.EventID, "at": m.At, "subject": m.Subject, "link": m.Link},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.secret.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "zanskar-notify")
	req.Header.Set("X-Zanskar-Timestamp", ts)
	req.Header.Set("X-Zanskar-Signature", "sha256="+audit.Sign([]byte(c.secret.SigningKey), ts, body))
	rt := s.Transport
	if rt == nil {
		rt = &http.Transport{DialContext: guardedDialer(s.AllowLoopback).DialContext, TLSHandshakeTimeout: sendTimeout, ForceAttemptHTTP2: true}
	}
	client := http.Client{Transport: rt, Timeout: sendTimeout,
		// A redirect re-posts the body: never followed.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("the webhook could not be reached: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the webhook answered %d", resp.StatusCode)
	}
	return nil
}

// email sends the message over SMTP: TLS from the start on port 465, else
// STARTTLS, which is required unless the server is this host's own; the
// account's password is sent only over TLS.
func (s *Sender) email(ctx context.Context, c *Channel, m Message) error {
	cfg := c.Config
	if cfg.SMTPHost == "" || len(cfg.To) == 0 || cfg.From == "" {
		return errors.New("the email channel needs a server, a sender and recipients")
	}
	port := cfg.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(port))
	dialer := guardedDialer(true)
	tlsCfg := &tls.Config{ServerName: cfg.SMTPHost, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	var err error
	if port == 465 {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("the mail server could not be reached: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	cl, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("the mail server did not greet: %w", err)
	}
	defer func() { _ = cl.Close() }()
	if port != 465 {
		if ok, _ := cl.Extension("STARTTLS"); ok {
			if err := cl.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("the mail server's TLS failed: %w", err)
			}
		} else if !isLocal(cfg.SMTPHost) {
			return errors.New("the mail server offers no STARTTLS; mail is sent only over TLS")
		}
	}
	if cfg.SMTPUsername != "" {
		if err := cl.Auth(smtp.PlainAuth("", cfg.SMTPUsername, c.secret.SMTPPassword, cfg.SMTPHost)); err != nil {
			return fmt.Errorf("the mail server refused the account: %w", err)
		}
	}
	if err := cl.Mail(cfg.From); err != nil {
		return fmt.Errorf("the mail server refused the sender: %w", err)
	}
	for _, to := range cfg.To {
		if err := cl.Rcpt(to); err != nil {
			return fmt.Errorf("the mail server refused %s: %w", to, err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(mailBody(cfg, m)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("the mail server did not take the message: %w", err)
	}
	return cl.Quit()
}

func isLocal(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// mailBody is the message as RFC 5322 text: the subject Q-encoded, the
// body plain UTF-8 with the link on its own line.
func mailBody(cfg Config, m Message) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", cfg.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(cfg.To, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", "Zanskar: "+m.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	fmt.Fprintf(&b, "%s\r\n", m.Text)
	if m.Link != "" {
		fmt.Fprintf(&b, "\r\n%s\r\n", m.Link)
	}
	fmt.Fprintf(&b, "\r\n-- \r\nZanskar, event %d at %s\r\n", m.EventID, m.At)
	return []byte(b.String())
}
