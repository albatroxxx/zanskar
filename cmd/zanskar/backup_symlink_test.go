// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBackupSkipsSymlinksInRecordings: the recordings directory belongs to
// the service user and backup usually runs as root, so a link planted there
// must not pull the file it points at into the archive (review finding
// SEC-5). Regular files are copied, the link is skipped and counted.
func TestBackupSkipsSymlinksInRecordings(t *testing.T) {
	g := newCLIGateway(t, true)
	if err := os.MkdirAll(filepath.Join(g.recDir, "2026"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(g.recDir, "2026", "r1.cast"), []byte("cast"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(g.dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("not a recording"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(g.recDir, "leak.cast")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(g.dir, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "o.cast"), []byte("elsewhere"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(g.recDir, "linked-dir")); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	_, stderr, err := output(t, func() error { return runBackup([]string{"-out", archive}) })
	if err != nil {
		t.Fatalf("backup: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "2 entries") || !strings.Contains(stderr, "not regular files") {
		t.Errorf("the skipped links were not reported:\n%s", stderr)
	}
	files := readTarGz(t, archive)
	if string(files["recordings/2026/r1.cast"]) != "cast" {
		t.Errorf("the regular recording was not copied: %v", keysOf(files))
	}
	for name, body := range files {
		if strings.Contains(name, "leak") || strings.Contains(name, "linked-dir") || string(body) == "not a recording" || string(body) == "elsewhere" {
			t.Errorf("a link's target reached the archive: %s", name)
		}
	}
}

// TestRestoreReplacesSymlinksInRecordings: a link already sitting where a
// restored file or directory goes is removed, never written through, so a
// restore as root cannot be steered into overwriting a file elsewhere.
func TestRestoreReplacesSymlinksInRecordings(t *testing.T) {
	src := newCLIGateway(t, true)
	if err := os.MkdirAll(filepath.Join(src.recDir, "2026"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src.recDir, "2026", "r1.cast"), []byte("cast"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src.recDir, "top.cast"), []byte("top"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	if _, stderr, err := output(t, func() error { return runBackup([]string{"-out", archive}) }); err != nil {
		t.Fatalf("backup: %v\n%s", err, stderr)
	}

	dst := newCLIGateway(t, false)
	if err := os.MkdirAll(dst.recDir, 0o700); err != nil {
		t.Fatal(err)
	}
	victimFile := filepath.Join(dst.dir, "victim.txt")
	if err := os.WriteFile(victimFile, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	victimDir := filepath.Join(dst.dir, "victim-dir")
	if err := os.MkdirAll(victimDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimFile, filepath.Join(dst.recDir, "top.cast")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimDir, filepath.Join(dst.recDir, "2026")); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := output(t, func() error { return runRestore([]string{"-in", archive, "-force"}) }); err != nil {
		t.Fatalf("restore: %v\n%s", err, stderr)
	}

	if b, err := os.ReadFile(victimFile); err != nil || string(b) != "keep me" {
		t.Fatalf("restore wrote through a link onto another file: %q %v", b, err)
	}
	if entries, err := os.ReadDir(victimDir); err != nil || len(entries) != 0 {
		t.Fatalf("restore wrote through a directory link: %v %v", entries, err)
	}
	for _, rel := range []string{"top.cast", "2026"} {
		info, err := os.Lstat(filepath.Join(dst.recDir, rel))
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			t.Errorf("%s is still a link: %v %v", rel, info, err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(dst.recDir, "top.cast")); err != nil || string(b) != "top" {
		t.Errorf("top.cast after restore: %q %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(dst.recDir, "2026", "r1.cast")); err != nil || string(b) != "cast" {
		t.Errorf("2026/r1.cast after restore: %q %v", b, err)
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
