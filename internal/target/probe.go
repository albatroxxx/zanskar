// SPDX-License-Identifier: Apache-2.0

package target

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Prober discovers what a target answers on and captures the material used
// for pinning: the SSH host key and the TLS certificate. It never
// authenticates; the SSH handshake is abandoned right after the host key
// arrives.
type Prober struct {
	// AllowLoopback disables the loopback refusal. Tests only.
	AllowLoopback bool
	// Resolver overrides DNS resolution; nil uses net.DefaultResolver.
	Resolver *net.Resolver
}

// PortResult is one protocol's outcome.
type PortResult struct {
	Reachable bool   `json:"reachable"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// SSHHostKey is what an SSH server presented.
type SSHHostKey struct {
	Fingerprint string `json:"fingerprint"` // SHA256:... as OpenSSH prints it
	Type        string `json:"type"`        // ssh-ed25519, ecdsa-sha2-nistp256, ...
	Banner      string `json:"banner"`      // SSH-2.0-OpenSSH_9.6
}

// TLSInfo is the leaf certificate an RDP or WinRM server presented.
type TLSInfo struct {
	Fingerprint string `json:"fingerprint"` // lowercase hex SHA-256 of the DER certificate
	Subject     string `json:"subject"`
	Source      string `json:"source"` // rdp | winrm
}

// ProbeResult is everything one probe learned.
type ProbeResult struct {
	Address      string                  `json:"address"`
	ResolvedIP   string                  `json:"resolved_ip"`
	Ports        map[Protocol]PortResult `json:"ports"`
	Capabilities []Protocol              `json:"capabilities"`
	SSHHostKey   *SSHHostKey             `json:"ssh_host_key,omitempty"`
	TLS          *TLSInfo                `json:"tls,omitempty"`
	VNCVersion   string                  `json:"vnc_version,omitempty"`
	ProbedAt     time.Time               `json:"probed_at"`

	// Reachable and Errors are convenience views of Ports.
	Reachable map[Protocol]bool   `json:"-"`
	Errors    map[Protocol]string `json:"-"`
}

// ErrAddressForbidden is returned for addresses the gateway must never probe.
var ErrAddressForbidden = errors.New("target: address refused: loopback, link-local or unspecified")

// Probe checks every protocol in ports concurrently. Resolution happens once
// and every connection goes to the resolved IP, so a DNS answer cannot change
// between the safety check and the connect.
func (p *Prober) Probe(ctx context.Context, address string, ports map[Protocol]int, timeout time.Duration) (ProbeResult, error) {
	res := ProbeResult{
		Address:   address,
		Ports:     map[Protocol]PortResult{},
		Reachable: map[Protocol]bool{},
		Errors:    map[Protocol]string{},
		ProbedAt:  time.Now().UTC(),
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ip, err := p.resolve(ctx, address)
	if err != nil {
		return res, err
	}
	res.ResolvedIP = ip.String()

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for proto, port := range ports {
		if !ValidProtocol(proto) || port < 1 || port > 65535 {
			continue
		}
		wg.Add(1)
		go func(proto Protocol, port int) {
			defer wg.Done()
			pr, ssh, tlsInfo, vnc := p.probeOne(ctx, proto, ip, port, address, timeout)
			mu.Lock()
			defer mu.Unlock()
			res.Ports[proto] = pr
			res.Reachable[proto] = pr.Reachable
			if pr.Error != "" {
				res.Errors[proto] = pr.Error
			}
			if ssh != nil {
				res.SSHHostKey = ssh
			}
			if tlsInfo != nil && (res.TLS == nil || proto == RDP) {
				res.TLS = tlsInfo
			}
			if vnc != "" {
				res.VNCVersion = vnc
			}
		}(proto, port)
	}
	wg.Wait()

	res.Capabilities = []Protocol{}
	for _, proto := range Protocols {
		if res.Reachable[proto] {
			res.Capabilities = append(res.Capabilities, proto)
		}
	}
	return res, nil
}

func (p *Prober) resolve(ctx context.Context, address string) (net.IP, error) {
	var ips []net.IP
	if ip := net.ParseIP(address); ip != nil {
		ips = []net.IP{ip}
	} else {
		r := p.Resolver
		if r == nil {
			r = net.DefaultResolver
		}
		addrs, err := r.LookupIPAddr(ctx, address)
		if err != nil {
			return nil, fmt.Errorf("target: resolve %s: %w", address, err)
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("target: resolve %s: no addresses", address)
	}
	// Every answer must be acceptable; an attacker-controlled name with one
	// good and one forbidden record must not slip through.
	for _, ip := range ips {
		if ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
			return nil, ErrAddressForbidden
		}
		if ip.IsLoopback() && !p.AllowLoopback {
			return nil, ErrAddressForbidden
		}
	}
	// Prefer IPv4 for reachability from typical gateway networks.
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip, nil
		}
	}
	return ips[0], nil
}

func (p *Prober) probeOne(ctx context.Context, proto Protocol, ip net.IP, port int, serverName string, timeout time.Duration) (PortResult, *SSHHostKey, *TLSInfo, string) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err != nil {
		return PortResult{Reachable: false, Error: shortErr(err)}, nil, nil, ""
	}
	defer conn.Close()
	pr := PortResult{Reachable: true, LatencyMS: time.Since(start).Milliseconds()}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)

	switch proto {
	case SSH:
		hk, err := probeSSH(conn, ip.String())
		if err != nil {
			pr.Error = shortErr(err)
		}
		return pr, hk, nil, ""
	case WinRM:
		info, err := probeTLS(ctx, conn, serverName, "winrm")
		if err != nil {
			pr.Error = shortErr(err)
		}
		return pr, nil, info, ""
	case RDP:
		info, err := probeRDP(ctx, conn, serverName)
		if err != nil {
			pr.Error = shortErr(err)
		}
		return pr, nil, info, ""
	case VNC:
		v, err := probeVNC(conn)
		if err != nil {
			pr.Error = shortErr(err)
		}
		return pr, nil, nil, v
	}
	return pr, nil, nil, ""
}

var errHostKeyCaptured = errors.New("host key captured")

// bannerConn replays the server version line we already consumed so the SSH
// client library can read it again.
type bannerConn struct {
	net.Conn
	r io.Reader
}

func (b *bannerConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func probeSSH(conn net.Conn, addr string) (*SSHHostKey, error) {
	br := bufio.NewReader(conn)
	var banner string
	// RFC 4253 allows lines before the version string; skip them (bounded).
	for i := 0; i < 20; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read banner: %w", err)
		}
		if strings.HasPrefix(line, "SSH-") {
			banner = strings.TrimRight(line, "\r\n")
			break
		}
	}
	if banner == "" {
		return nil, errors.New("no SSH banner")
	}
	hk := &SSHHostKey{Banner: banner}
	replay := &bannerConn{Conn: conn, r: io.MultiReader(bytes.NewReader([]byte(banner+"\r\n")), br)}
	cfg := &ssh.ClientConfig{
		User: "zanskar-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			hk.Fingerprint = ssh.FingerprintSHA256(key)
			hk.Type = key.Type()
			return errHostKeyCaptured
		},
	}
	_, _, _, err := ssh.NewClientConn(replay, addr, cfg)
	if hk.Fingerprint != "" {
		return hk, nil
	}
	if err == nil {
		err = errors.New("handshake finished without a host key")
	}
	return hk, fmt.Errorf("ssh handshake: %w", err)
}

func probeTLS(ctx context.Context, conn net.Conn, serverName, source string) (*TLSInfo, error) {
	cfg := &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- we capture the certificate to pin it; verification is the point of the pin
	if net.ParseIP(serverName) == nil {
		cfg.ServerName = serverName
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("tls: no certificate presented")
	}
	sum := sha256.Sum256(certs[0].Raw)
	return &TLSInfo{Fingerprint: hex.EncodeToString(sum[:]), Subject: certs[0].Subject.String(), Source: source}, nil
}

// probeRDP performs the X.224 connection request with an RDP_NEG_REQ asking
// for TLS (and CredSSP, which also starts with TLS). If the server agrees, the
// TLS handshake follows on the same connection and the certificate is captured.
func probeRDP(ctx context.Context, conn net.Conn, serverName string) (*TLSInfo, error) {
	req := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT: version 3, length 19
		0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 Connection Request
		0x01, 0x00, 0x08, 0x00, // RDP_NEG_REQ: type 1, flags 0, length 8
		0x03, 0x00, 0x00, 0x00, // requested protocols: TLS | CredSSP
	}
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("rdp negotiate: %w", err)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("rdp negotiate: %w", err)
	}
	if hdr[0] != 0x03 {
		return nil, errors.New("rdp: not a TPKT response")
	}
	length := int(hdr[2])<<8 | int(hdr[3])
	if length < 11 || length > 64 {
		return nil, errors.New("rdp: bad negotiation response length")
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("rdp negotiate: %w", err)
	}
	if body[1] != 0xd0 { // X.224 Connection Confirm
		return nil, errors.New("rdp: unexpected X.224 response")
	}
	if len(body) < 15 {
		return nil, errors.New("rdp: server uses standard RDP security; no TLS certificate to pin")
	}
	neg := body[7:]
	switch neg[0] {
	case 0x02: // RDP_NEG_RSP
		selected := uint32(neg[4]) | uint32(neg[5])<<8 | uint32(neg[6])<<16 | uint32(neg[7])<<24
		if selected == 0 {
			return nil, errors.New("rdp: server selected standard RDP security")
		}
		return probeTLS(ctx, conn, serverName, "rdp")
	case 0x03: // RDP_NEG_FAILURE
		code := uint32(neg[4]) | uint32(neg[5])<<8 | uint32(neg[6])<<16 | uint32(neg[7])<<24
		return nil, fmt.Errorf("rdp: negotiation failure code %d", code)
	}
	return nil, errors.New("rdp: unknown negotiation response")
}

func probeVNC(conn net.Conn) (string, error) {
	buf := make([]byte, 12)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", fmt.Errorf("vnc banner: %w", err)
	}
	s := string(buf)
	if !strings.HasPrefix(s, "RFB ") {
		return "", errors.New("vnc: not an RFB banner")
	}
	return strings.TrimSpace(s), nil
}

func shortErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	s := err.Error()
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}
