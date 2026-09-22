// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestSQLiteFilePath(t *testing.T) {
	cases := []struct {
		dsn  string
		want string
		ok   bool
	}{
		{"file:/var/lib/zanskar/zanskar.db?_pragma=foreign_keys(1)", "/var/lib/zanskar/zanskar.db", true},
		{"file:zanskar.db", "zanskar.db", true},
		{"/abs/path.db", "/abs/path.db", true},
		{"file::memory:", "", false},
		{"file:test.db?mode=memory&cache=shared", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, err := sqliteFilePath(tc.dsn)
		if tc.ok && (err != nil || got != tc.want) {
			t.Errorf("sqliteFilePath(%q) = %q,%v; want %q,nil", tc.dsn, got, err, tc.want)
		}
		if !tc.ok && err == nil {
			t.Errorf("sqliteFilePath(%q) should error", tc.dsn)
		}
	}
}

func TestKeyFingerprint(t *testing.T) {
	a := keyFingerprint([]byte("some-32-byte-master-key-aaaaaaaa"))
	if len(a) != 16 {
		t.Fatalf("fingerprint length = %d, want 16", len(a))
	}
	if a == keyFingerprint([]byte("a-different-master-key-bbbbbbbbbb")) {
		t.Fatal("different keys must fingerprint differently")
	}
	if a != keyFingerprint([]byte("some-32-byte-master-key-aaaaaaaa")) {
		t.Fatal("fingerprint must be stable")
	}
}

func TestTarGzRoundTrip(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "db"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "recordings"), 0o750); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"manifest.json":         `{"v":1}`,
		"db/zanskar.db":         "SQLITE-BYTES",
		"recordings/sess1.cast": "hello-recording",
	}
	for rel, content := range files {
		if err := os.WriteFile(filepath.Join(src, rel), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	arc := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := writeTarGz(src, arc); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := extractTarGz(arc, dst); err != nil {
		t.Fatal(err)
	}
	for rel, want := range files {
		got, err := os.ReadFile(filepath.Join(dst, rel))
		if err != nil {
			t.Fatalf("missing %s after round trip: %v", rel, err)
		}
		if string(got) != want {
			t.Fatalf("%s = %q, want %q", rel, got, want)
		}
	}
}

// TestExtractTarGzRejectsTraversal is the security-critical case: an archive
// entry that would escape the destination must be refused, not written.
func TestExtractTarGzRejectsTraversal(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("pwned")
	hdr := &tar.Header{Name: "../escape.txt", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gz.Close()

	arc := filepath.Join(t.TempDir(), "evil.tar.gz")
	if err := os.WriteFile(arc, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := extractTarGz(arc, dst); err == nil {
		t.Fatal("extract must reject a path-traversal entry")
	}
	// And nothing must have been written outside the destination.
	if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "escape.txt")); err == nil {
		t.Fatal("traversal entry escaped the destination")
	}
}

// TestExtractTarGzRejectsOversizedEntry guards the disk-exhaustion cap: an entry
// whose header claims an enormous size must be refused before any bytes flow.
func TestExtractTarGzRejectsOversizedEntry(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	// A header claiming far more than the cap; no body is written, so this is
	// cheap to construct and must be rejected on the size check alone.
	hdr := &tar.Header{Name: "huge.bin", Mode: 0o600, Size: maxRestoreEntryBytes + 1, Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gz.Close()

	arc := filepath.Join(t.TempDir(), "huge.tar.gz")
	if err := os.WriteFile(arc, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractTarGz(arc, t.TempDir()); err == nil {
		t.Fatal("extract must reject an entry whose size exceeds the cap")
	}
}
