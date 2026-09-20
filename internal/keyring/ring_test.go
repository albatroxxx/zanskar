// SPDX-License-Identifier: Apache-2.0

package keyring

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/store"
)

func newDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func kek(t *testing.T, fill byte) crypto.KEKProvider {
	t.Helper()
	k, err := crypto.NewLocalKEK(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestBootstrapAndReopen(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)

	r1, err := Open(ctx, db, kek(t, 1))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if r1.ActiveVersion() != 1 {
		t.Fatalf("active = %d, want 1", r1.ActiveVersion())
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM key_versions`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("key_versions rows = %d (%v), want 1", n, err)
	}

	aad := AAD("credentials", "abc")
	ct, ver, err := r1.Encrypt(aad, []byte("hunter2"))
	if err != nil || ver != 1 {
		t.Fatalf("encrypt: %v ver=%d", err, ver)
	}

	r2, err := Open(ctx, db, kek(t, 1))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if r2.ActiveVersion() != 1 {
		t.Fatalf("reopen active = %d", r2.ActiveVersion())
	}
	pt, err := r2.Decrypt(aad, ct, ver)
	if err != nil || string(pt) != "hunter2" {
		t.Fatalf("decrypt after reopen: %v %q", err, pt)
	}

	if _, err := r2.Decrypt(AAD("credentials", "other"), ct, ver); !errors.Is(err, crypto.ErrInvalidCiphertext) {
		t.Fatalf("wrong aad: got %v", err)
	}
	if _, err := r2.Decrypt(aad, ct, 9); err == nil || !strings.Contains(err.Error(), "version 9") {
		t.Fatalf("unknown version: got %v", err)
	}
}

func TestWrongMasterKey(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	if _, err := Open(ctx, db, kek(t, 1)); err != nil {
		t.Fatal(err)
	}
	_, err := Open(ctx, db, kek(t, 2))
	if err == nil || !strings.Contains(err.Error(), "version 1") {
		t.Fatalf("expected unwrap failure naming version 1, got %v", err)
	}
}

func TestRotate(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	r, err := Open(ctx, db, kek(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	aad := AAD("credentials", "x")
	ctOld, verOld, err := r.Encrypt(aad, []byte("old"))
	if err != nil {
		t.Fatal(err)
	}

	newVer, err := r.Rotate(ctx)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newVer != 2 || r.ActiveVersion() != 2 {
		t.Fatalf("after rotate: new=%d active=%d", newVer, r.ActiveVersion())
	}
	ctNew, verNew, err := r.Encrypt(aad, []byte("new"))
	if err != nil || verNew != 2 {
		t.Fatalf("encrypt after rotate: %v ver=%d", err, verNew)
	}
	if pt, err := r.Decrypt(aad, ctOld, verOld); err != nil || string(pt) != "old" {
		t.Fatalf("old version must still decrypt: %v %q", err, pt)
	}
	if pt, err := r.Decrypt(aad, ctNew, verNew); err != nil || string(pt) != "new" {
		t.Fatalf("new version decrypt: %v %q", err, pt)
	}

	// A fresh ring with the same KEK sees both versions.
	r2, err := Open(ctx, db, kek(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if r2.ActiveVersion() != 2 {
		t.Fatalf("reopened active = %d", r2.ActiveVersion())
	}
	if _, err := r2.Decrypt(aad, ctOld, 1); err != nil {
		t.Fatalf("reopened ring cannot decrypt v1: %v", err)
	}
}

func TestClose(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	r, err := Open(ctx, db, kek(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	r.mu.RLock()
	dek := r.deks[1]
	r.mu.RUnlock()
	copyBefore := append([]byte(nil), dek...)
	if bytes.Equal(copyBefore, make([]byte, 32)) {
		t.Fatal("dek should not be all zero before close")
	}
	r.Close()
	if !bytes.Equal(dek, make([]byte, 32)) {
		t.Fatal("dek not zeroed on close")
	}
	if _, _, err := r.Encrypt("a", []byte("b")); !errors.Is(err, ErrClosed) {
		t.Fatalf("encrypt after close: %v", err)
	}
	if _, err := r.Rotate(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("rotate after close: %v", err)
	}
}
