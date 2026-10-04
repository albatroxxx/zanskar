// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGuacStreamSizeAndHash: a desktop recording's size and SHA-256 are those
// of exactly the bytes written, which is what a reviewer later checks a
// download against; closing twice reports the same, and nothing more can be
// written once it is closed.
func TestGuacStreamSizeAndHash(t *testing.T) {
	st := &LocalStorage{Dir: t.TempDir()}
	g, uri, err := NewGuacStream(context.Background(), st, "d1.guac")
	if err != nil {
		t.Fatal(err)
	}
	parts := []string{"4.size,1.0,4.1024,3.768;", "4.sync,8.12345678;", "3.png,1.0,2.15,1.0,1.0,4.AAAA;"}
	for _, p := range parts {
		if err := g.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	size, sum, err := g.Close()
	want := strings.Join(parts, "")
	wantSum := sha256.Sum256([]byte(want))
	if err != nil || size != int64(len(want)) || sum != hex.EncodeToString(wantSum[:]) {
		t.Fatalf("close: %d %s %v", size, sum, err)
	}
	if got, _ := os.ReadFile(filepath.Join(st.Dir, "d1.guac")); string(got) != want || !strings.HasSuffix(uri, "d1.guac") {
		t.Fatalf("stored %q at %s", got, uri)
	}
	if size2, sum2, err := g.Close(); err != nil || size2 != size || sum2 != sum {
		t.Fatalf("second close: %d %s %v", size2, sum2, err)
	}
	if err := g.Write("4.sync;"); err == nil {
		t.Fatal("a closed recording accepted more data")
	}
}

// TestAsciicastLeavesKeystrokesOutByDefault: what a user types often holds
// passwords, so a terminal recording keeps the screen but not the keys
// unless input recording is switched on.
func TestAsciicastLeavesKeystrokesOutByDefault(t *testing.T) {
	st := &LocalStorage{Dir: t.TempDir()}
	for _, on := range []bool{false, true} {
		name := map[bool]string{false: "off.cast", true: "on.cast"}[on]
		a, _, err := NewAsciicast(context.Background(), st, name, Header{Width: 80, Height: 24})
		if err != nil {
			t.Fatal(err)
		}
		a.RecordInput = on
		_ = a.Output([]byte("Password: "))
		_ = a.Input([]byte("hunter2-typed"))
		if err := a.Flush(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := a.Close(); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(filepath.Join(st.Dir, name))
		if strings.Contains(string(got), "hunter2-typed") != on {
			t.Fatalf("RecordInput=%v: keystrokes in the recording = %v", on, !on)
		}
	}
}

// TestRouterDelete: deletion goes to the store the URI names; a recording
// in S3 is not silently "deleted" when no S3 store is configured.
func TestRouterDelete(t *testing.T) {
	ctx := context.Background()
	st := &LocalStorage{Dir: t.TempDir()}
	r := &Router{Local: st}
	w, uri, err := st.Create(ctx, "x.cast")
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if err := r.Delete(ctx, uri); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(st.Dir, "x.cast")); !os.IsNotExist(err) {
		t.Fatal("the local recording is still there")
	}
	if err := r.Delete(ctx, "s3://recs/recordings/x.cast"); err == nil {
		t.Fatal("deleting an S3 recording without an S3 store must fail, not pass")
	}
}
