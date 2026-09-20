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
	defer rows.Close()

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
