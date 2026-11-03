// SPDX-License-Identifier: Apache-2.0

package ipspace

import (
	"net"
	"testing"
)

func TestReserved(t *testing.T) {
	cases := []struct{ ip, want string }{
		// Public, in both families, and an IPv4 address written as IPv6.
		{"93.184.216.34", ""},
		{"1.1.1.1", ""},
		{"2606:4700:4700::1111", ""},
		{"::ffff:93.184.216.34", ""},
		// What a page must never reach through the gateway.
		{"127.0.0.1", "loopback"},
		{"::1", "loopback"},
		{"::ffff:127.0.0.1", "loopback"},
		{"10.0.0.5", "private"},
		{"172.16.0.1", "private"},
		{"192.168.1.1", "private"},
		{"::ffff:10.0.0.1", "private"},
		{"fd00::1", "private"},
		{"169.254.169.254", "link-local"},
		{"169.254.170.2", "link-local"},
		{"fe80::1", "link-local"},
		{"fd00:ec2::254", "a cloud metadata service"},
		{"100.100.100.200", "a cloud metadata service"},
		{"168.63.129.16", "a cloud metadata service"},
		{"192.0.0.192", "a cloud metadata service"},
		{"100.64.0.1", "shared address space (carrier-grade NAT)"},
		{"192.0.0.9", "IETF protocol assignments"},
		{"0.0.0.0", "unspecified"},
		{"::", "unspecified"},
		{"0.1.2.3", "this network"},
		{"224.0.0.1", "link-local"}, // link-local multicast, in Go's words
		{"ff02::1", "link-local"},
		{"239.255.255.250", "multicast"},
		{"ff0e::1", "multicast"},
		{"255.255.255.255", "broadcast"},
		{"240.0.0.1", "reserved"},
		{"198.18.0.1", "benchmarking"},
		{"192.0.2.1", "documentation"},
		{"198.51.100.1", "documentation"},
		{"203.0.113.1", "documentation"},
		{"2001:db8::1", "documentation"},
		{"64:ff9b::a00:1", "NAT64"},
		{"2002:a00:1::", "6to4"},
		{"2001:0:4136:e378:8000:63bf:3fff:fdd2", "Teredo"},
		{"fec0::1", "site-local"},
		{"100::1", "discard"},
	}
	for _, c := range cases {
		if got := Reserved(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("Reserved(%s) = %q, want %q", c.ip, got, c.want)
		}
	}
	if got := Reserved(nil); got != "not an address" {
		t.Errorf("Reserved(nil) = %q", got)
	}
}
