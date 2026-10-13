// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
)

// ErrAddressForbidden is returned for an address the gateway must never
// connect to; the message says which address and why.
var ErrAddressForbidden = errors.New("target: address refused")

// Resolver is the part of *net.Resolver the address rules use, so tests can
// answer lookups themselves.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// metadataAddrs are cloud platform services outside the link-local range,
// which already covers 169.254.169.254 (AWS, Azure, GCP, OCI), ECS's
// 169.254.170.2 and EKS Pod Identity's 169.254.170.23. Each is refused by its
// exact address, so a neighbour is still a target: Alibaba's sits in the shared
// address space that carrier-grade NAT and Tailscale also use, and Oracle's in
// a block of protocol assignments.
var metadataAddrs = []net.IP{
	net.ParseIP("fd00:ec2::254"),   // AWS instance metadata over IPv6
	net.ParseIP("fd00:ec2::23"),    // EKS Pod Identity over IPv6, which hands pods AWS credentials
	net.ParseIP("100.100.100.200"), // Alibaba Cloud metadata
	net.ParseIP("168.63.129.16"),   // Azure WireServer: VM agent and extension settings, sometimes with secrets
	net.ParseIP("192.0.0.192"),     // Oracle Cloud's legacy metadata endpoint
}

// refusal says why the gateway must never connect to ip, or is empty when it
// may. The net.IP tests see through IPv4-mapped IPv6, so ::ffff:127.0.0.1 is
// loopback too.
func (p *Prober) refusal(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsLoopback() && !p.AllowLoopback:
		return "loopback"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local"
	case ip.IsMulticast():
		return "multicast"
	case p.Self != nil && ip.Equal(p.Self):
		return "the address the gateway listens on"
	}
	if slices.ContainsFunc(metadataAddrs, ip.Equal) {
		return "a cloud metadata service"
	}
	return ""
}

// refuse applies the rules to one answer for address, which is that answer
// itself when literal.
func (p *Prober) refuse(address string, ip net.IP, literal bool) error {
	why := p.refusal(ip)
	switch {
	case why == "":
		return nil
	case literal:
		return fmt.Errorf("%w: %s is %s", ErrAddressForbidden, address, why)
	}
	return fmt.Errorf("%w: %s resolves to %s, which is %s", ErrAddressForbidden, address, ip, why)
}

// Resolve looks address up once and applies the rules to every answer, so a
// name with one acceptable and one forbidden record is refused. It returns
// the answer to connect to, IPv4 first for reachability from typical gateway
// networks. Whoever dials must use that answer, not the name: a second lookup
// can answer differently (DNS rebinding). A nil Prober applies the rules with
// no exception.
func (p *Prober) Resolve(ctx context.Context, address string) (net.IP, error) {
	if p == nil {
		p = &Prober{}
	}
	if ip := net.ParseIP(address); ip != nil {
		if err := p.refuse(address, ip, true); err != nil {
			return nil, err
		}
		return ip, nil
	}
	var r Resolver = net.DefaultResolver
	if p.Resolver != nil {
		r = p.Resolver
	}
	addrs, err := r.LookupIPAddr(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("target: resolve %s: %w", address, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("target: resolve %s: no addresses", address)
	}
	for _, a := range addrs {
		if err := p.refuse(address, a.IP, false); err != nil {
			return nil, err
		}
	}
	for _, a := range addrs {
		if a.IP.To4() != nil {
			return a.IP, nil
		}
	}
	return addrs[0].IP, nil
}

// CheckLiteral applies the rules to an address that is an IP literal, as a
// target is saved. A name passes: what it resolves to can change, so it is
// checked each time it is looked up, by the probe and by every session. A
// nil Prober applies the rules with no exception.
func (p *Prober) CheckLiteral(address string) error {
	if p == nil {
		p = &Prober{}
	}
	address = strings.TrimSpace(address)
	ip := net.ParseIP(address)
	if ip == nil {
		return nil
	}
	return p.refuse(address, ip, true)
}

// ListenIP is the address the gateway's listener is bound to when listenAddr
// (ZANSKAR_LISTEN_ADDR) names one, and nil when it binds every address
// (0.0.0.0, :: or no host), names a host, or does not parse. The host's other
// addresses are deliberately not looked up: a single-machine demo enrols the
// host's own LAN address as a target.
func ListenIP(listenAddr string) net.IP {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return nil
	}
	return ip
}
