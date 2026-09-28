// SPDX-License-Identifier: Apache-2.0

// Package settings holds the runtime settings an administrator edits in the
// console and the gateway applies live, without a restart: one row per key
// in the settings table. Boot settings (listen address, database, master
// key) are environment, read once at start (ADR 0014); everything that can
// change while the service runs belongs here.
package settings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/albatroxxx/zanskar/internal/store"
)

// Keys.
const (
	// KeyLoginBanner is the system-use notification shown on the sign-in
	// page before any credential is entered (NIST AC-8). Empty hides it.
	KeyLoginBanner = "login_banner"
)

// MaxLoginBanner bounds the banner: long enough for a legal notice, short
// enough that the sign-in form stays on the page.
const MaxLoginBanner = 4000

// Setting is one stored value with who last changed it.
type Setting struct {
	Key       string     `json:"key"`
	Value     string     `json:"value"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
}

// ErrInvalid marks a value the key does not accept.
var ErrInvalid = errors.New("settings: invalid value")

// Repo reads and writes settings.
type Repo struct{ db *store.DB }

// NewRepo returns a repository over db.
func NewRepo(db *store.DB) *Repo { return &Repo{db: db} }

// Get returns the setting, or an empty one for a key never set.
func (r *Repo) Get(ctx context.Context, key string) (Setting, error) {
	s := Setting{Key: key}
	var updated store.NullTime
	var by sql.NullString
	err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT value, updated_at, updated_by FROM settings WHERE key = ?`), key).Scan(&s.Value, &updated, &by)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return s, nil
		}
		return s, fmt.Errorf("settings: get %s: %w", key, err)
	}
	s.UpdatedAt, s.UpdatedBy = updated.Ptr(), by.String
	return s, nil
}

// Set validates and stores a value, recording who set it.
func (r *Repo) Set(ctx context.Context, key, value, actorUserID string) (Setting, error) {
	value, err := Validate(key, value)
	if err != nil {
		return Setting{}, err
	}
	now := time.Now().UTC()
	_, err = r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`),
		key, value, store.TimeArg(now), sql.NullString{String: actorUserID, Valid: actorUserID != ""})
	if err != nil {
		return Setting{}, fmt.Errorf("settings: set %s: %w", key, err)
	}
	return r.Get(ctx, key)
}

// Validate normalises a value for its key and refuses what the key does not
// accept. The login banner is plain text: trimmed, line endings unified,
// bounded in length, valid UTF-8.
func Validate(key, value string) (string, error) {
	switch key {
	case KeyLoginBanner:
		v := strings.TrimSpace(strings.ReplaceAll(value, "\r\n", "\n"))
		if !utf8.ValidString(v) {
			return "", fmt.Errorf("%w: banner must be valid UTF-8", ErrInvalid)
		}
		if utf8.RuneCountInString(v) > MaxLoginBanner {
			return "", fmt.Errorf("%w: banner must be at most %d characters", ErrInvalid, MaxLoginBanner)
		}
		return v, nil
	default:
		return "", fmt.Errorf("%w: unknown setting %q", ErrInvalid, key)
	}
}
