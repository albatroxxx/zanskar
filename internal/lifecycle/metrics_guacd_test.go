// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestMetricsGuacdCheckStaysOnTheGatewaysNetwork: the reachability check
// dials the guacd address a runtime setting names. An address outside the
// gateway's own network is refused before any packet is sent, so the check
// is not a reachability oracle for arbitrary hosts (threat model risk 7);
// a loopback guacd is still reported reachable.
func TestMetricsGuacdCheckStaysOnTheGatewaysNetwork(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	probe := func(addr string) (reachable bool, took time.Duration) {
		h := &Handler{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), StartedAt: time.Now(), GuacdAddr: func() string { return addr }}
		rr := httptest.NewRecorder()
		started := time.Now()
		h.metrics(rr, httptest.NewRequest("GET", "/api/v1/admin/system/metrics", nil))
		took = time.Since(started)
		var out struct {
			Guacd *GuacdCheck `json:"guacd"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || rr.Code != http.StatusOK || out.Guacd == nil || out.Guacd.Address != addr {
			t.Fatalf("metrics for %s: %d %s (%v)", addr, rr.Code, rr.Body.String(), err)
		}
		return out.Guacd.Reachable, took
	}
	if ok, _ := probe(ln.Addr().String()); !ok {
		t.Fatal("a loopback guacd must be reported reachable")
	}
	ok, took := probe("203.0.113.9:4822")
	if ok {
		t.Fatal("a public address must never be reported reachable")
	}
	if took > guacdDialTimeout/2 {
		t.Fatalf("the public address was dialled (took %v); it must be refused before the dial", took)
	}
}
