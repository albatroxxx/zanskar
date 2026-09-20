// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestAsciicastRoundTrip(t *testing.T) {
	st := &LocalStorage{Dir: t.TempDir()}
	ctx := context.Background()
	a, uri, err := NewAsciicast(ctx, st, "s1.cast", Header{Width: 80, Height: 24, Title: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "file://") {
		t.Fatalf("bad uri %q", uri)
	}
	_ = a.Output([]byte("$ ls\r\n"))
	_ = a.Input([]byte("secret")) // not recorded by default
	_ = a.Resize(120, 40)
	_ = a.Marker("failover")
	size, sum, err := a.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Close(); err != nil {
		t.Fatal("double close must be harmless")
	}
	if err := a.Output([]byte("late")); err == nil {
		t.Fatal("write after close must fail")
	}

	rc, err := st.Open(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	raw, _ := io.ReadAll(rc)
	if int64(len(raw)) != size {
		t.Fatalf("size %d != %d", len(raw), size)
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != sum {
		t.Fatal("digest mismatch")
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Scan()
	var hdr Header
	if err := json.Unmarshal(sc.Bytes(), &hdr); err != nil || hdr.Version != 2 || hdr.Width != 80 || hdr.Timestamp == 0 {
		t.Fatalf("bad header %s: %v", sc.Text(), err)
	}
	var kinds []string
	for sc.Scan() {
		var ev []any
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil || len(ev) != 3 {
			t.Fatalf("bad event %s", sc.Text())
		}
		kinds = append(kinds, ev[1].(string))
	}
	if strings.Join(kinds, "") != "orm" {
		t.Fatalf("expected events o,r,m got %v", kinds)
	}
}

func TestLocalStorageGuards(t *testing.T) {
	st := &LocalStorage{Dir: t.TempDir()}
	ctx := context.Background()
	if _, _, err := st.Create(ctx, "../escape.cast"); err == nil {
		t.Fatal("path traversal in name must be refused")
	}
	if _, err := st.Open(ctx, "file:///etc/passwd"); err == nil {
		t.Fatal("open outside dir must be refused")
	}
	if _, _, err := st.Create(ctx, "dup.cast"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Create(ctx, "dup.cast"); err == nil {
		t.Fatal("overwrite must be refused")
	}
}
