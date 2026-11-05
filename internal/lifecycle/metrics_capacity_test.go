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

// TestImagesReadAgainSoonAfterAnEmptyRead (2026-11-05, live): the first read
// runs as the gateway starts, before an update's images are pulled, and found
// nothing; that was kept five minutes. An empty read, or a failed one, is tried
// again within seconds; a found size is kept the full five minutes.
func TestImagesReadAgainSoonAfterAnEmptyRead(t *testing.T) {
	var reads atomic.Int32
	var size atomic.Int64
	c := &imagesCache{}
	read := func() *int64 {
		return c.read(func(context.Context) (int64, error) { reads.Add(1); return size.Load(), nil })
	}
	settle := func() {
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			c.mu.Lock()
			done := !c.reading
			c.mu.Unlock()
			if done {
				return
			}
		}
		t.Fatal("the read did not end")
	}
	ago := func(d time.Duration) {
		c.mu.Lock()
		c.at = time.Now().Add(-d)
		c.mu.Unlock()
	}

	read() // as the gateway starts: nothing pulled yet
	settle()
	if got := read(); got == nil || *got != 0 || reads.Load() != 1 {
		t.Fatalf("an empty first read: %v, %d reads", got, reads.Load())
	}
	ago(imagesRetry - 5*time.Second) // sooner than the retry: no new read
	read()
	if reads.Load() != 1 {
		t.Fatalf("read again before the retry: %d", reads.Load())
	}
	size.Store(900_000_000) // the images have been pulled
	ago(imagesRetry + time.Second)
	read()
	settle()
	if got := read(); got == nil || *got != 900_000_000 || reads.Load() != 2 {
		t.Fatalf("after the retry: %v, %d reads", got, reads.Load())
	}
	// A size that was found, once the gateway has settled, is kept the full
	// five minutes, not retried.
	c.mu.Lock()
	c.first = time.Now().Add(-imagesSettle - time.Second)
	c.mu.Unlock()
	ago(imagesRetry + time.Second)
	read()
	if reads.Load() != 2 {
		t.Fatalf("a found size was read again after only the retry interval: %d", reads.Load())
	}
	ago(imagesEvery + time.Second)
	read()
	settle()
	if reads.Load() != 3 {
		t.Fatalf("not read again after five minutes: %d", reads.Load())
	}
}

// TestImagesReadAgainWhileTheGatewaySettles (2026-11-05, live, 1.18.6): an
// update pulls the gateway's image and, nine seconds later, the browser's; a
// read between them found 20 MB of the 272 and kept it five minutes. Whatever
// a read found, the size is read again every few seconds for the first two
// minutes, and kept five minutes after that.
func TestImagesReadAgainWhileTheGatewaySettles(t *testing.T) {
	var reads atomic.Int32
	var size atomic.Int64
	c := &imagesCache{}
	read := func() *int64 {
		return c.read(func(context.Context) (int64, error) { reads.Add(1); return size.Load(), nil })
	}
	settle := func() {
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			c.mu.Lock()
			done := !c.reading
			c.mu.Unlock()
			if done {
				return
			}
		}
		t.Fatal("the read did not end")
	}
	ago := func(d time.Duration) {
		c.mu.Lock()
		c.at = time.Now().Add(-d)
		c.mu.Unlock()
	}

	size.Store(20_000_000) // the gateway's image only
	read()
	settle()
	if got := read(); got == nil || *got != 20_000_000 {
		t.Fatalf("the partial read: %v", got)
	}
	size.Store(272_000_000) // the browser's image has arrived
	ago(imagesRetry + time.Second)
	read()
	settle()
	if got := read(); got == nil || *got != 272_000_000 || reads.Load() != 2 {
		t.Fatalf("a partial read was kept: %v, %d reads", got, reads.Load())
	}
	// Settled: a size is kept for the five minutes.
	c.mu.Lock()
	c.first = time.Now().Add(-imagesSettle - time.Second)
	c.mu.Unlock()
	ago(imagesRetry + time.Second)
	read()
	if reads.Load() != 2 {
		t.Fatalf("read again after settling: %d", reads.Load())
	}
}

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
