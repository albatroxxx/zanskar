// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// noAppend is a storage that takes no line after the close, as an object
// store does: the Storage methods and nothing more.
type noAppend struct{ Storage }

// Flush puts what the buffer holds in storage without closing, so a
// recording kept open after its session (ADR 0050, phase C) is on disk up to
// the session's end; Close after it measures the whole. AppendMarker adds a
// marker and an output line after the writer is gone, timed from the
// header, which Markers reads back; a storage that cannot append says so,
// and a blob that is not an asciicast is refused.
func TestFlushAndAppendMarker(t *testing.T) {
	ctx := context.Background()
	st := &LocalStorage{Dir: t.TempDir()}
	started := time.Now().Add(-90 * time.Second)
	a, uri, err := NewAsciicast(ctx, st, "s.cast", Header{Width: 80, Height: 24, Timestamp: started.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Marker("session started")
	_ = a.Output([]byte("session started\r\n"))
	path := strings.TrimPrefix(uri, "file://")
	if b, _ := os.ReadFile(path); strings.Contains(string(b), "session started") { // #nosec G304 -- the test's own temp dir
		t.Fatal("the buffer reached the disk before a flush")
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	flushed, _ := os.ReadFile(path) // #nosec G304 -- the test's own temp dir
	if !strings.Contains(string(flushed), `"m","session started"`) || !strings.HasPrefix(string(flushed), `{"version":2,`) {
		t.Fatalf("after the flush:\n%s", flushed)
	}
	size, sum, err := a.Close()
	if err != nil || size != int64(len(flushed)) {
		t.Fatalf("close: %d %q %v, want the flushed %d bytes", size, sum, err, len(flushed))
	}
	if msize, msum, _ := Measure(ctx, st, uri); msize != size || msum != sum {
		t.Fatalf("measure %d %q, close %d %q", msize, msum, size, sum)
	}
	if err := a.Flush(); err != nil {
		t.Fatalf("a flush after the close: %v", err)
	}

	if err := AppendMarker(ctx, st, uri, "activity not read: gateway restarted"); err != nil {
		t.Fatal(err)
	}
	rc, err := st.Open(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	markers, err := Markers(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(markers) != 2 || markers[1].Label != "activity not read: gateway restarted" {
		t.Fatalf("markers: %+v", markers)
	}
	// Timed from the header: about ninety seconds in.
	if markers[1].At < 85*time.Second || markers[1].At > 120*time.Second {
		t.Fatalf("the appended line is at %v, want about 90 seconds", markers[1].At)
	}
	after, _ := os.ReadFile(path) // #nosec G304 -- the test's own temp dir
	if !strings.HasSuffix(string(after), `"o","activity not read: gateway restarted\r\n"]`+"\n") || !strings.HasPrefix(string(after), string(flushed)) {
		t.Fatalf("after the append:\n%s", after)
	}
	if msize, _, _ := Measure(ctx, st, uri); msize != int64(len(after)) {
		t.Fatalf("measure after the append: %d, want %d", msize, len(after))
	}

	if err := AppendMarker(ctx, noAppend{st}, uri, "x"); !errors.Is(err, ErrNoAppend) {
		t.Fatalf("a storage without Append: %v", err)
	}
	w, other, err := st.Create(ctx, "other.guac")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("4.sync,8.12345678;"))
	_ = w.Close()
	if err := AppendMarker(ctx, st, other, "x"); err == nil || !strings.Contains(err.Error(), "not an asciicast header") {
		t.Fatalf("a guac stream: %v", err)
	}
	if _, err := st.Append(ctx, "file:///etc/passwd"); err == nil || !strings.Contains(err.Error(), "outside storage directory") {
		t.Fatalf("append outside the directory: %v", err)
	}
}
