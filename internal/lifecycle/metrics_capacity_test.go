// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/gateway"
)

// TestMetricsCapacity (2026-10-31): application and database sessions
// counted from the registry beside their caps, and the images' size read in
// the background, at most every five minutes; a failed read leaves it out.
func TestMetricsCapacity(t *testing.T) {
	reg := gateway.NewRegistry()
	reg.Add(context.Background(), gateway.Live{SessionID: "a1", Protocol: "http"})
	reg.Add(context.Background(), gateway.Live{SessionID: "a2", Protocol: "http"})
	reg.Add(context.Background(), gateway.Live{SessionID: "d1", Protocol: "database"})
	reg.Add(context.Background(), gateway.Live{SessionID: "s1", Protocol: "ssh"})
	var reads atomic.Int32
	var fail atomic.Bool
	release := make(chan struct{})
	h := &Handler{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), StartedAt: time.Now(), Controller: &Controller{Registry: reg},
		AppsMaxSessions: 10, DatabaseMaxSessions: 20,
		ImagesSize: func(context.Context) (int64, error) {
			reads.Add(1)
			<-release
			if fail.Load() {
				return 0, errors.New("cannot connect to the Docker daemon")
			}
			return 900_000_000, nil
		}}
	get := func() Metrics {
		t.Helper()
		rr := httptest.NewRecorder()
		h.metrics(rr, httptest.NewRequest("GET", "/api/v1/admin/system/metrics", nil))
		var m Metrics
		if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	// until polls the metrics until ok holds, or fails after five seconds.
	until := func(what string, ok func(Metrics) bool) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			if ok(get()) {
				return
			}
		}
		t.Fatalf("timed out waiting for %s", what)
	}

	// The reader hangs, as a stuck daemon does: the metrics answer anyway,
	// without the size, and a second request starts no second read.
	m := get()
	if m.ApplicationSessions != 2 || m.DatabaseSessions != 1 || m.SessionCaps.Applications != 10 || m.SessionCaps.Databases != 20 {
		t.Fatalf("sessions and caps: %+v", m)
	}
	if m.ImagesBytes != nil {
		t.Fatalf("images before the first read ended: %v", *m.ImagesBytes)
	}
	get()
	until("the read to start", func(Metrics) bool { return reads.Load() == 1 })
	close(release)
	until("the size", func(m Metrics) bool { return m.ImagesBytes != nil && *m.ImagesBytes == 900_000_000 })
	get()
	if n := reads.Load(); n != 1 {
		t.Fatalf("the images were read %d times within five minutes, want once", n)
	}

	// Five minutes on, the next read fails: the size is left out.
	h.images.mu.Lock()
	h.images.at = time.Now().Add(-imagesEvery - time.Second)
	h.images.mu.Unlock()
	fail.Store(true)
	until("a failed read to clear the size", func(m Metrics) bool { return m.ImagesBytes == nil })
	if n := reads.Load(); n != 2 {
		t.Fatalf("reads = %d, want 2", n)
	}
}
