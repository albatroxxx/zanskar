// SPDX-License-Identifier: Apache-2.0

// Package ipspace says which part of the address space an IP address is in:
// public, or one of the special-purpose ranges a connection made on a web
// page's say-so must never reach. The target address rules
// (internal/target) and the application relay (internal/gateway/apprelay)
// both read it, so what counts as a cloud metadata service is written once.
package ipspace

import (
	"net"
	"slices"
)

// Metadata are cloud platform services outside the link-local range, which
// already covers 169.254.169.254 (AWS, Azure, GCP, OCI), ECS's 169.254.170.2
// and EKS Pod Identity's 169.254.170.23. Each is refused by its exact
// address, so a neighbour is still a target: Alibaba's sits in the shared
// address space that carrier-grade NAT and Tailscale also use, and Oracle's
// in a block of protocol assignments.
var Metadata = []net.IP{
	net.ParseIP("fd00:ec2::254"),   // AWS instance metadata over IPv6
	net.ParseIP("fd00:ec2::23"),    // EKS Pod Identity over IPv6, which hands pods AWS credentials
	net.ParseIP("100.100.100.200"), // Alibaba Cloud metadata
	net.ParseIP("168.63.129.16"),   // Azure WireServer: VM agent and extension settings, sometimes with secrets
	net.ParseIP("192.0.0.192"),     // Oracle Cloud's legacy metadata endpoint
}

// IsMetadata reports whether ip is one of Metadata.
func IsMetadata(ip net.IP) bool { return slices.ContainsFunc(Metadata, ip.Equal) }

// reserved are the special-purpose ranges the net.IP tests do not cover,
// each with the words that say what it is (RFC 6890 and the IANA
// special-purpose registries). An IPv6 range that carries an IPv4 address
// inside it (NAT64, 6to4, Teredo) is reserved as a whole: what it maps to
// is not checked, so it is not trusted.
var reserved = func() []struct {
	net  *net.IPNet
	what string
} {
	var out []struct {
		net  *net.IPNet
		what string
	}
	for _, r := range []struct{ cidr, what string }{
		{"0.0.0.0/8", "this network"},
		{"100.64.0.0/10", "shared address space (carrier-grade NAT)"},
		{"192.0.0.0/24", "IETF protocol assignments"},
		{"192.0.2.0/24", "documentation"},
		{"198.51.100.0/24", "documentation"},
		{"203.0.113.0/24", "documentation"},
		{"198.18.0.0/15", "benchmarking"},
		{"240.0.0.0/4", "reserved"},
		{"2001:db8::/32", "documentation"},
		{"64:ff9b::/96", "NAT64"},
		{"64:ff9b:1::/48", "local NAT64"},
		{"2002::/16", "6to4"},
		{"2001::/32", "Teredo"},
		{"fec0::/10", "site-local"},
		{"100::/64", "discard"},
	} {
		_, n, err := net.ParseCIDR(r.cidr)
		if err != nil {
			panic(err)
		}
		out = append(out, struct {
			net  *net.IPNet
			what string
		}{n, r.what})
	}
	return out
}()

// Reserved says what special-purpose space ip is in, in words, or "" when
// ip is a public address: one a page may be let fetch from. The net.IP
// tests see through IPv4-mapped IPv6, so ::ffff:10.0.0.1 is private too.
func Reserved(ip net.IP) string {
	switch {
	case ip == nil:
		return "not an address"
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local"
	case ip.IsMulticast():
		return "multicast"
	// Before private: AWS's IPv6 metadata address is unique local too, and
	// the more telling words win.
	case IsMetadata(ip):
		return "a cloud metadata service"
	case ip.IsPrivate():
		return "private"
	case ip.Equal(net.IPv4bcast):
		return "broadcast"
	}
	for _, r := range reserved {
		if r.net.Contains(ip) {
			return r.what
		}
	}
	return ""
}
