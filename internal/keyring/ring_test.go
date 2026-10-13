// SPDX-License-Identifier: Apache-2.0

package keyring

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

func newDB(t *testing.T) *store.DB {
	return storetest.Open(t)
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

// TestRewrap covers master-key rotation: after Rewrap every version opens
// with the new key and none with the old, secret ciphertext sealed before
// and after is unchanged and still readable, and rewrapping onto the key
// already in use is refused.
func TestRewrap(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	r, err := Open(ctx, db, kek(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	aad := AAD("credentials", "c1")
	ct1, v1, err := r.Encrypt(aad, []byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	ct2, v2, err := r.Encrypt(aad, []byte("second"))
	if err != nil || v2 != 2 {
		t.Fatalf("encrypt under v2: %v %d", err, v2)
	}

	if _, err := r.Rewrap(ctx, kek(t, 1)); !errors.Is(err, ErrSameKEK) {
		t.Fatalf("rewrap onto the same key must be refused, got %v", err)
	}
	n, err := r.Rewrap(ctx, kek(t, 9))
	if err != nil || n != 2 {
		t.Fatalf("rewrap: n=%d err=%v", n, err)
	}
	// The live ring keeps working, and the ciphertext did not change.
	for _, c := range []struct {
		ct   []byte
		v    int
		want string
	}{{ct1, v1, "first"}, {ct2, v2, "second"}} {
		if pt, err := r.Decrypt(aad, c.ct, c.v); err != nil || string(pt) != c.want {
			t.Fatalf("decrypt after rewrap (v%d): %v %q", c.v, err, pt)
		}
	}
	// A new key encrypts under the active version as before.
	if _, v3, err := r.Encrypt(aad, []byte("third")); err != nil || v3 != 2 {
		t.Fatalf("encrypt after rewrap: %v %d", err, v3)
	}
	// Reopening: the new key opens both versions, the old key opens nothing.
	r2, err := Open(ctx, db, kek(t, 9))
	if err != nil {
		t.Fatalf("reopen with the new key: %v", err)
	}
	if pt, err := r2.Decrypt(aad, ct1, v1); err != nil || string(pt) != "first" {
		t.Fatalf("new key must read old ciphertext: %v %q", err, pt)
	}
	if _, err := Open(ctx, db, kek(t, 1)); err == nil || !strings.Contains(err.Error(), "cannot unwrap key version") {
		t.Fatalf("old key must no longer open the ring, got %v", err)
	}
	var rotated string
	if err := db.QueryRowContext(ctx, `SELECT rotated_at FROM key_versions WHERE id = 1`).Scan(&rotated); err != nil || rotated == "" {
		t.Fatalf("rotated_at should record the rewrap: %q %v", rotated, err)
	}
}

// TestKeyVersionTimesAreStored: created_at and rotated_at are written in the
// form every timestamp is stored in (store.TimeArg, M28), not as RFC 3339
// whole seconds, so they compare as times with the rest on SQLite.
func TestKeyVersionTimesAreStored(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	r, err := Open(ctx, db, kek(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Rewrap(ctx, kek(t, 2)); err != nil {
		t.Fatal(err)
	}
	rows, err := db.QueryContext(ctx, `SELECT created_at, rotated_at FROM key_versions ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var created, rotated string
		if err := rows.Scan(&created, &rotated); err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{created, rotated} {
			at, err := time.Parse(time.RFC3339Nano, v)
			if err != nil || v != store.TimeArg(at) || len(v) != len("2006-01-02T15:04:05.000000Z") {
				t.Errorf("key version %d: %q is not stored as store.TimeArg writes it (%v)", n+1, v, err)
			}
		}
		n++
	}
	if err := rows.Err(); err != nil || n != 2 {
		t.Fatalf("key versions read: %d %v", n, err)
	}
}

// TestDecryptPicksUpVersionsAddedElsewhere: a ring loaded its versions once
// (B7), so after `zanskar key rotate` (or another gateway) added a version,
// a running gateway reported every secret sealed under it as "unknown or
// retired" until restarted. Meeting a version it does not hold, the ring
// reads the table again and decrypts.
func TestDecryptPicksUpVersionsAddedElsewhere(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	k := kek(t, 3)
	running, err := Open(ctx, db, k)
	if err != nil {
		t.Fatal(err)
	}
	defer running.Close()
	cli, err := Open(ctx, db, k)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	v2, err := cli.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ct, ver, err := cli.Encrypt(AAD("credentials", "c1"), []byte("pw-under-v2"))
	if err != nil || ver != v2 {
		t.Fatalf("encrypt: version %d (%v), want %d", ver, err, v2)
	}
	pt, err := running.Decrypt(AAD("credentials", "c1"), ct, ver)
	if err != nil || string(pt) != "pw-under-v2" {
		t.Fatalf("the running ring must pick up version %d: %q %v", ver, pt, err)
	}
	if _, err := running.Decrypt(AAD("credentials", "c1"), ct, 99); err == nil {
		t.Fatal("a version that exists nowhere must still be refused")
	}
}
