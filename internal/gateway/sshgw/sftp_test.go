// SPDX-License-Identifier: Apache-2.0

package sshgw

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"
)

func TestSFTPRoundTrip(t *testing.T) {
	fs := startFakeServer(t)
	client, err := Dial(context.Background(), endpoint(fs, true), Auth{Username: "test", Password: "pw"}, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	s, err := OpenSFTP(client)
	if err != nil {
		t.Fatalf("open sftp: %v", err)
	}
	defer func() { _ = s.Close() }()

	dir := t.TempDir()

	// Upload.
	f, err := s.Create(filepath.Join(dir, "hello.txt"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.Write([]byte("hi from sftp")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// List.
	entries, err := s.List(dir)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "hello.txt" || entries[0].Dir || entries[0].Size != 12 {
		t.Fatalf("unexpected listing: %+v", entries)
	}

	// Download.
	rf, fi, err := s.Open(filepath.Join(dir, "hello.txt"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = rf.Close() }()
	if fi.Size() != 12 {
		t.Fatalf("size = %d, want 12", fi.Size())
	}
	got, err := io.ReadAll(rf)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hi from sftp" {
		t.Fatalf("content = %q", got)
	}

	// Opening a directory as a file is refused.
	if _, _, err := s.Open(dir); err == nil {
		t.Fatal("expected an error opening a directory as a file")
	}
}
