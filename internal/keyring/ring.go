// SPDX-License-Identifier: Apache-2.0

// Package keyring manages data-encryption key (DEK) versions on top of the
// envelope primitives in internal/crypto (ADR 0007).
//
// Every DEK lives in the key_versions table wrapped by the key-encryption key
// (KEK) provider. The highest non-retired version is active and is used for
// new encryptions; older versions stay loaded so existing ciphertext can still
// be decrypted after a rotation. Owners re-encrypt their rows lazily.
//
// AAD convention: every ciphertext is bound to its owning row with additional
// authenticated data of the form "<table>:<row id>", built with AAD. A
// ciphertext copied into a different row therefore fails to decrypt. Wrapped
// DEKs themselves use "key_versions:<id>".
package keyring

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/store"
)

const (
	algorithm = "aes-256-gcm"
	// bootstrapLockID is the Postgres advisory lock key that serialises
	// concurrent bootstraps across gateways. Arbitrary but fixed.
	bootstrapLockID = 7213_0001
)

// ErrClosed is returned after Close.
var ErrClosed = errors.New("keyring: closed")

// ErrSameKEK is returned by Rewrap when the new master key is the current one.
var ErrSameKEK = errors.New("keyring: the new master key is the one already in use")

// AAD builds the additional authenticated data for a row: "<table>:<id>".
func AAD(table, id string) string {
	return table + ":" + id
}

// Ring holds unwrapped DEKs in memory and encrypts with the active one.
type Ring struct {
	db  *store.DB
	kek crypto.KEKProvider

	mu     sync.RWMutex
	deks   map[int][]byte
	active int
	closed bool
}

// Open loads every non-retired key version, unwrapping each DEK with kek, and
// bootstraps version 1 when the table is empty.
func Open(ctx context.Context, db *store.DB, kek crypto.KEKProvider) (*Ring, error) {
	r := &Ring{db: db, kek: kek, deks: map[int][]byte{}}
	if err := r.load(ctx); err != nil {
		return nil, err
	}
	if r.active == 0 {
		if _, err := r.createVersion(ctx, true); err != nil {
			return nil, err
		}
		if err := r.load(ctx); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// load reads all non-retired versions and replaces the in-memory set.
func (r *Ring) load(ctx context.Context) error {
	rows, err := r.db.QueryContext(ctx, `SELECT id, wrapped_dek FROM key_versions WHERE retired_at IS NULL ORDER BY id`)
	if err != nil {
		return fmt.Errorf("keyring: read key_versions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	deks := map[int][]byte{}
	active := 0
	for rows.Next() {
		var id int
		var wrapped []byte
		if err := rows.Scan(&id, &wrapped); err != nil {
			return fmt.Errorf("keyring: scan key_versions: %w", err)
		}
		dek, err := r.kek.Unwrap(ctx, wrapped, []byte(AAD("key_versions", strconv.Itoa(id))))
		if err != nil {
			for _, d := range deks {
				crypto.Zero(d)
			}
			return fmt.Errorf("keyring: cannot unwrap key version %d with the configured KEK (%s); wrong master key or KEK reference", id, r.kek.Source())
		}
		deks[id] = dek
		if id > active {
			active = id
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("keyring: iterate key_versions: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for id, old := range r.deks {
		if _, still := deks[id]; !still {
			crypto.Zero(old)
		}
	}
	// Prefer already-held copies so Zero on reload does not race readers.
	for id, d := range deks {
		if held, ok := r.deks[id]; ok {
			crypto.Zero(d)
			deks[id] = held
		}
	}
	r.deks = deks
	r.active = active
	return nil
}

// createVersion inserts a new wrapped DEK. When onlyIfEmpty is set, it is a
// bootstrap: the insert is skipped if another gateway got there first.
func (r *Ring) createVersion(ctx context.Context, onlyIfEmpty bool) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("keyring: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if r.db.Driver == config.DriverPostgres {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, bootstrapLockID); err != nil {
			return 0, fmt.Errorf("keyring: advisory lock: %w", err)
		}
	}

	var maxID sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(id) FROM key_versions`).Scan(&maxID); err != nil {
		return 0, fmt.Errorf("keyring: read max version: %w", err)
	}
	if onlyIfEmpty && maxID.Valid {
		return int(maxID.Int64), nil // someone else bootstrapped; caller reloads
	}
	newID := int(maxID.Int64) + 1

	dek, err := crypto.NewDEK()
	if err != nil {
		return 0, err
	}
	defer crypto.Zero(dek)
	wrapped, err := r.kek.Wrap(ctx, dek, []byte(AAD("key_versions", strconv.Itoa(newID))))
	if err != nil {
		return 0, fmt.Errorf("keyring: wrap dek: %w", err)
	}

	_, err = tx.ExecContext(ctx, r.db.Rebind(
		`INSERT INTO key_versions (id, algorithm, kek_source, kek_ref, wrapped_dek, created_at) VALUES (?, ?, ?, NULL, ?, ?)`),
		newID, algorithm, r.kek.Source(), wrapped, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("keyring: insert key version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("keyring: commit: %w", err)
	}
	return newID, nil
}

// ActiveVersion returns the version used for new encryptions.
func (r *Ring) ActiveVersion() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active
}

// Encrypt seals plaintext with the active DEK and returns the version used.
func (r *Ring) Encrypt(aad string, plaintext []byte) ([]byte, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, 0, ErrClosed
	}
	dek, ok := r.deks[r.active]
	if !ok {
		return nil, 0, errors.New("keyring: no active key version")
	}
	ct, err := crypto.Encrypt(dek, plaintext, []byte(aad))
	if err != nil {
		return nil, 0, err
	}
	return ct, r.active, nil
}

// Decrypt opens ciphertext produced under keyVersion with the same aad.
func (r *Ring) Decrypt(aad string, ciphertext []byte, keyVersion int) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, ErrClosed
	}
	dek, ok := r.deks[keyVersion]
	if !ok {
		return nil, fmt.Errorf("keyring: key version %d is unknown or retired", keyVersion)
	}
	return crypto.Decrypt(dek, ciphertext, []byte(aad))
}

// Rotate creates a new DEK version and makes it active. Earlier versions stay
// loaded for decryption.
func (r *Ring) Rotate(ctx context.Context) (int, error) {
	r.mu.RLock()
	closed := r.closed
	r.mu.RUnlock()
	if closed {
		return 0, ErrClosed
	}
	id, err := r.createVersion(ctx, false)
	if err != nil {
		return 0, err
	}
	if err := r.load(ctx); err != nil {
		return 0, err
	}
	return id, nil
}

// Rewrap re-seals every non-retired DEK under newKEK in one transaction and
// switches the ring to it. This is master-key rotation (ADR 0007, amended
// 2026-09-28): secrets are sealed under DEKs, never under the master key, so
// their ciphertext is untouched and the operation is a handful of small rows
// however many secrets there are. Once every DEK a leaked master key could
// open has been rewrapped, that key opens nothing in this database. A
// database that leaked together with the key is a different incident: the
// DEKs, and so the secrets, were exposed, and only rotating those secrets at
// their targets remedies it.
//
// Each new wrapping is verified by unwrapping it before anything is
// committed, and the whole set is one transaction, so the table is never
// left half under one key and half under another. Returns the number of
// versions rewrapped.
func (r *Ring) Rewrap(ctx context.Context, newKEK crypto.KEKProvider) (int, error) {
	r.mu.RLock()
	closed, oldKEK := r.closed, r.kek
	r.mu.RUnlock()
	if closed {
		return 0, ErrClosed
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("keyring: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if r.db.Driver == config.DriverPostgres {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, bootstrapLockID); err != nil {
			return 0, fmt.Errorf("keyring: advisory lock: %w", err)
		}
	}
	// Read the whole set first and close the cursor: SQLite runs on one
	// connection and the updates below would otherwise deadlock behind it.
	type row struct {
		id      int
		wrapped []byte
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, wrapped_dek FROM key_versions WHERE retired_at IS NULL ORDER BY id`)
	if err != nil {
		return 0, fmt.Errorf("keyring: read key_versions: %w", err)
	}
	var set []row
	for rows.Next() {
		var rw row
		if err := rows.Scan(&rw.id, &rw.wrapped); err != nil {
			_ = rows.Close() //nolint:sqlclosecheck // explicit close on SQLite's single connection; updates follow
			return 0, fmt.Errorf("keyring: scan key_versions: %w", err)
		}
		set = append(set, rw)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("keyring: iterate key_versions: %w", err)
	}
	_ = rows.Close() // SQLite single connection: close before the updates below
	if len(set) == 0 {
		return 0, errors.New("keyring: no key versions to rewrap")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, rw := range set {
		aad := []byte(AAD("key_versions", strconv.Itoa(rw.id)))
		// If the new key already opens the old wrapping it is the same key,
		// and "rotating" to it would only look like a rotation.
		if probe, err := newKEK.Unwrap(ctx, rw.wrapped, aad); err == nil {
			crypto.Zero(probe)
			return 0, ErrSameKEK
		}
		dek, err := oldKEK.Unwrap(ctx, rw.wrapped, aad)
		if err != nil {
			return 0, fmt.Errorf("keyring: cannot unwrap key version %d with the current master key: %w", rw.id, err)
		}
		wrapped, err := newKEK.Wrap(ctx, dek, aad)
		if err != nil {
			crypto.Zero(dek)
			return 0, fmt.Errorf("keyring: wrap key version %d: %w", rw.id, err)
		}
		check, err := newKEK.Unwrap(ctx, wrapped, aad)
		same := err == nil && len(check) == len(dek) && subtleEqual(check, dek)
		crypto.Zero(check)
		crypto.Zero(dek)
		if !same {
			return 0, fmt.Errorf("keyring: verification of rewrapped key version %d failed; nothing was changed", rw.id)
		}
		if _, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE key_versions SET wrapped_dek = ?, kek_source = ?, kek_ref = NULL, rotated_at = ? WHERE id = ?`),
			wrapped, newKEK.Source(), now, rw.id); err != nil {
			return 0, fmt.Errorf("keyring: update key version %d: %w", rw.id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("keyring: commit: %w", err)
	}
	r.mu.Lock()
	r.kek = newKEK
	r.mu.Unlock()
	return len(set), nil
}

// subtleEqual compares two DEKs without leaking where they differ.
func subtleEqual(a, b []byte) bool {
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// Close zeroes every DEK held in memory. The Ring is unusable afterwards.
func (r *Ring) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.deks {
		crypto.Zero(d)
	}
	r.deks = map[int][]byte{}
	r.active = 0
	r.closed = true
}
