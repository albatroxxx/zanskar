// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// ErrKeyRequired: the account must use its security key, so a code from its
// authenticator app is refused (Administrators must use a security key, ADR
// 0028). A recovery code is still accepted. Not a wrong code: nothing is
// counted.
var ErrKeyRequired = errors.New("auth: this account signs in with its security key")

// Factors are an account's second factors together: its authenticator app
// and its security keys (ADR 0028). Everything that asks whether an account
// has a second factor, checks a typed code, or clears them asks here.
type Factors struct {
	TOTP *TOTP
	Keys *Keys
	db   *store.DB
	// KeyRequired, when set, reports whether the account must answer with
	// its key: its app's codes are then refused.
	KeyRequired func(ctx context.Context, userID string) (bool, error)
}

// NewFactors joins an account's app and keys.
func NewFactors(db *store.DB, totp *TOTP, keys *Keys) *Factors {
	return &Factors{TOTP: totp, Keys: keys, db: db}
}

// Methods reports whether the account's app is confirmed and how many keys
// it has.
func (f *Factors) Methods(ctx context.Context, userID string) (app bool, keys int, err error) {
	if app, err = f.TOTP.Enrolled(ctx, userID); err != nil {
		return false, 0, err
	}
	keys, err = f.Keys.Count(ctx, userID)
	return app, keys, err
}

// Enrolled reports whether the account has a second factor: a confirmed app
// or at least one key.
func (f *Factors) Enrolled(ctx context.Context, userID string) (bool, error) {
	app, keys, err := f.Methods(ctx, userID)
	return app || keys > 0, err
}

// Verify checks a typed code: one from the account's app, or an unused
// recovery code, which is used up. An account with keys and no app types
// only recovery codes. It returns whether a recovery code was used; an
// account with neither factor answers ErrTOTPNotEnrolled, a wrong code
// ErrTOTPBadCode, and an app code from an account that must use its key
// ErrKeyRequired.
func (f *Factors) Verify(ctx context.Context, userID, code string) (bool, error) {
	app, keys, err := f.Methods(ctx, userID)
	if err != nil {
		return false, err
	}
	if !app && keys == 0 {
		return false, ErrTOTPNotEnrolled
	}
	keyOnly := !app
	if app && keys > 0 && f.KeyRequired != nil {
		if keyOnly, err = f.KeyRequired(ctx, userID); err != nil {
			return false, err
		}
	}
	if !keyOnly {
		return f.TOTP.Verify(ctx, userID, code)
	}
	used, err := f.TOTP.consumeRecovery(ctx, userID, strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	switch {
	case err != nil:
		return false, err
	case used:
		return true, nil
	case app && isAppCode(code):
		return false, ErrKeyRequired
	}
	return false, ErrTOTPBadCode
}

// isAppCode reports whether code has the shape of an authenticator app's.
func isAppCode(code string) bool {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// AddKey registers the key the browser just created, under name. An account
// with no second factor before it gets its recovery codes now, returned
// once; one that has a factor keeps the codes it has.
func (f *Factors) AddKey(ctx context.Context, sessionID string, u *user.User, name string, body []byte) (*Key, []string, error) {
	name, err := keyName(name)
	if err != nil {
		return nil, nil, err
	}
	cred, err := f.Keys.verifyRegistration(ctx, sessionID, u, body)
	if err != nil {
		return nil, nil, err
	}
	app, err := f.TOTP.Enrolled(ctx, u.ID)
	if err != nil {
		return nil, nil, err
	}
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	var before int
	if err := tx.QueryRowContext(ctx, f.db.Rebind(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`), u.ID).Scan(&before); err != nil {
		return nil, nil, err
	}
	key, err := f.Keys.insert(ctx, tx, u.ID, name, cred)
	if err != nil {
		return nil, nil, err
	}
	var codes []string
	if !app && before == 0 {
		if codes, err = replaceRecoveryCodes(ctx, f.db, tx, u.ID); err != nil {
			return nil, nil, err
		}
	}
	return key, codes, tx.Commit()
}

// RemoveKey removes one of the account's keys and returns its name. The last
// second factor of an account that must have one is not removed
// (ErrLastFactor).
func (f *Factors) RemoveKey(ctx context.Context, userID, id string, mustKeep bool) (string, error) {
	// Read before the transaction: SQLite has one connection, and the
	// transaction holds it.
	app, err := f.TOTP.Enrolled(ctx, userID)
	if err != nil {
		return "", err
	}
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck
	var name string
	err = tx.QueryRowContext(ctx, f.db.Rebind(`SELECT name FROM webauthn_credentials WHERE id = ? AND user_id = ?`), id, userID).Scan(&name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrKeyNotFound
		}
		return "", err
	}
	if mustKeep {
		var keys int
		if err := tx.QueryRowContext(ctx, f.db.Rebind(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`), userID).Scan(&keys); err != nil {
			return "", err
		}
		if keys == 1 && !app {
			return "", ErrLastFactor
		}
	}
	if _, err := tx.ExecContext(ctx, f.db.Rebind(`DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`), id, userID); err != nil {
		return "", err
	}
	return name, tx.Commit()
}

// ErrLastFactor: removing this would leave an account that must have a
// second factor without one.
var ErrLastFactor = errors.New("auth: this is the account's last second factor")

// NewRecoveryCodes replaces the account's recovery codes; the old ones stop
// working at once. An account with no second factor has none to replace.
func (f *Factors) NewRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	enrolled, err := f.Enrolled(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !enrolled {
		return nil, ErrTOTPNotEnrolled
	}
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	codes, err := replaceRecoveryCodes(ctx, f.db, tx, userID)
	if err != nil {
		return nil, err
	}
	return codes, tx.Commit()
}

// Reset removes the account's app, every key and every recovery code. It is
// what an administrator's Reset authenticator does, through ResetMFA.
func (f *Factors) Reset(ctx context.Context, userID string) error {
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	for _, q := range []string{
		`DELETE FROM mfa_totp WHERE user_id = ?`,
		`DELETE FROM mfa_recovery_codes WHERE user_id = ?`,
		`DELETE FROM webauthn_credentials WHERE user_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, f.db.Rebind(q), userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
