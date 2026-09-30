// SPDX-License-Identifier: Apache-2.0

package winrmgw

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
	"github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
)

// ErrCertMismatch is returned when the WinRM listener presents a certificate
// other than the one pinned at probe time. Mirrors RDP's cert-fingerprints.
var ErrCertMismatch = errors.New("winrmgw: server certificate does not match the pinned fingerprint")

// ErrUnpinned is returned when TLS is requested with neither a pinned
// fingerprint nor a CA bundle, and Insecure was not explicitly chosen.
var ErrUnpinned = errors.New("winrmgw: tls target has no pinned certificate; probe the target first")

// pinnedTransport is a winrm.Transporter whose TLS trust is a single leaf
// certificate fingerprint captured by the probe. The winrm library only
// offers "verify against a CA bundle" or "skip verification"; Windows hosts
// almost always use self-signed WinRM listener certificates, so pinning the
// leaf is the practical equivalent of SSH host key pinning.
//
// The library keeps the endpoint URL and credentials in unexported fields, so
// this transport carries its own copies.
type pinnedTransport struct {
	url      string
	user     string
	password string
	pin      []byte // SHA-256 of the DER leaf certificate
	ntlm     bool
	rt       http.RoundTripper
}

func newPinnedTransport(host string, port int, user, password, fingerprintHex string, ntlm bool) (*pinnedTransport, error) {
	pin, err := hex.DecodeString(strings.ToLower(strings.ReplaceAll(fingerprintHex, ":", "")))
	if err != nil || len(pin) != sha256.Size {
		return nil, fmt.Errorf("winrmgw: pinned fingerprint must be 64 hex characters: %w", err)
	}
	return &pinnedTransport{
		url:  "https://" + net.JoinHostPort(host, fmt.Sprint(port)) + "/wsman",
		user: user, password: password, pin: pin, ntlm: ntlm,
	}, nil
}

// Transport builds the HTTP transport. Verification is delegated entirely to
// the fingerprint check, so InsecureSkipVerify is set to bypass the CA and
// hostname checks that a self-signed listener certificate cannot pass.
// VerifyConnection (not VerifyPeerCertificate) is used because it also runs on
// resumed sessions, and session tickets are disabled so every connection
// performs a full handshake against the pin.
func (p *pinnedTransport) Transport(endpoint *winrm.Endpoint) error {
	tr := &http.Transport{
		Proxy: nil, // never route a target connection through an environment proxy
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify:     true, // #nosec G402 -- trust is the pinned leaf fingerprint in VerifyConnection
			MinVersion:             tls.VersionTLS12,
			SessionTicketsDisabled: true,
			VerifyConnection:       p.verifyConn,
		},
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout: endpoint.Timeout,
	}
	var rt http.RoundTripper = tr
	if p.ntlm {
		rt = &ntlmssp.Negotiator{RoundTripper: tr}
	}
	p.rt = rt
	return nil
}

func (p *pinnedTransport) verifyConn(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return ErrCertMismatch
	}
	sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
	if !hmac.Equal(sum[:], p.pin) {
		return ErrCertMismatch
	}
	return nil
}

// Post sends one SOAP envelope, matching the library's own Post semantics.
func (p *pinnedTransport) Post(_ *winrm.Client, request *soap.SoapMessage) (string, error) {
	client := &http.Client{Transport: p.rt}
	req, err := http.NewRequest(http.MethodPost, p.url, strings.NewReader(request.String())) //nolint:noctx // library contract has no context
	if err != nil {
		return "", fmt.Errorf("winrmgw: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.SetBasicAuth(p.user, p.password) // the NTLM negotiator reads credentials from here
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return "", fmt.Errorf("winrmgw: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("winrmgw: http %d: %s", resp.StatusCode, faultSummary(body))
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "application/soap+xml") {
		return "", errors.New("winrmgw: unexpected content type from server")
	}
	return string(body), nil
}

var (
	faultCodeRe = regexp.MustCompile(`WSManFault[^>]*\bCode="(-?[0-9]+)"`)
	faultMsgRe  = regexp.MustCompile(`(?s)<f:Message[^>]*>(.*?)</f:Message>`)
	faultTextRe = regexp.MustCompile(`(?s)<[a-zA-Z]*:?Text[^>]*>(.*?)</[a-zA-Z]*:?Text>`)
	tagRe       = regexp.MustCompile(`<[^>]+>`)
	spaceRe     = regexp.MustCompile(`\s+`)
)

// faultSummary turns a WS-Management error body into one short line. The useful
// part of a SOAP fault sits past several hundred bytes of namespace
// declarations, so printing the first bytes of the envelope says nothing at all
// and hides, for example, the access-denied fault behind an HTTP 500.
func faultSummary(b []byte) string {
	body := string(b)
	var parts []string
	if m := faultCodeRe.FindStringSubmatch(body); m != nil {
		parts = append(parts, "wsman fault "+m[1])
	}
	msg := ""
	if m := faultMsgRe.FindStringSubmatch(body); m != nil {
		msg = m[1]
	} else if m := faultTextRe.FindStringSubmatch(body); m != nil {
		msg = m[1]
	}
	if msg = collapse(msg); msg != "" {
		parts = append(parts, msg)
	}
	if len(parts) == 0 {
		return truncate(collapse(body), 256)
	}
	return truncate(strings.Join(parts, ": "), 512)
}

// collapse strips tags and entities from extracted fault text and folds
// whitespace, so a multi-line Windows message becomes one readable line.
func collapse(s string) string {
	s = tagRe.ReplaceAllString(s, " ")
	s = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&", "&quot;", `"`, "&#39;", "'").Replace(s)
	return strings.TrimSpace(spaceRe.ReplaceAllString(s, " "))
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
