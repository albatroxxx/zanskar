// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
)

// TOTP errors.
var (
	ErrTOTPNotEnrolled = errors.New("auth: totp not enrolled")
	ErrTOTPBadCode     = errors.New("auth: invalid code")
)

const recoveryCodeCount = 8

// TOTP manages time-based one-time password enrollment and verification.
// Secrets are sealed with the key ring; recovery codes are stored hashed.
type TOTP struct {
	db     *store.DB
	ring   *keyring.Ring
	Issuer string
	now    func() time.Time
}

// NewTOTP returns a manager. issuer appears in authenticator apps.
func NewTOTP(db *store.DB, ring *keyring.Ring, issuer string) *TOTP {
	return &TOTP{db: db, ring: ring, Issuer: issuer, now: time.Now}
}

// Enrollment is returned once; the secret is never readable again.
type Enrollment struct {
	Secret string `json:"secret"`      // base32, for manual entry
	URL    string `json:"otpauth_url"` // for QR rendering client-side
}

// Enrolled reports whether the user has a confirmed authenticator.
func (t *TOTP) Enrolled(ctx context.Context, userID string) (bool, error) {
	var confirmed store.NullTime
	err := t.db.QueryRowContext(ctx, t.db.Rebind(`SELECT confirmed_at FROM mfa_totp WHERE user_id = ?`), userID).Scan(&confirmed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return confirmed.Valid, nil
}

// Enroll generates a new secret in the unconfirmed state, replacing any
// previous unconfirmed one. A confirmed authenticator is not replaced; the
// caller must reset it first (an admin action) so a stolen session cannot
// silently swap the second factor.
func (t *TOTP) Enroll(ctx context.Context, userID, username string) (*Enrollment, error) {
	enrolled, err := t.Enrolled(ctx, userID)
	if err != nil {
		return nil, err
	}
	if enrolled {
		return nil, errors.New("auth: totp already enrolled; reset it first")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: t.Issuer, AccountName: username, SecretSize: 20, Algorithm: otp.AlgorithmSHA1, Digits: otp.DigitsSix,
	})
	if err != nil {
		return nil, err
	}
	sealed, ver, err := t.ring.Encrypt(keyring.AAD("mfa_totp", userID), []byte(key.Secret()))
	if err != nil {
		return nil, err
	}
	now := store.TimeArg(t.now())
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, t.db.Rebind(`DELETE FROM mfa_totp WHERE user_id = ?`), userID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, t.db.Rebind(`INSERT INTO mfa_totp (user_id, secret_enc, key_version, created_at) VALUES (?, ?, ?, ?)`),
		userID, sealed, ver, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Enrollment{Secret: key.Secret(), URL: key.URL()}, nil
}

// Confirm validates the first code from the authenticator, marks the
// enrollment confirmed and returns fresh recovery codes, shown once.
func (t *TOTP) Confirm(ctx context.Context, userID, code string) ([]string, error) {
	secret, confirmed, err := t.secret(ctx, userID)
	if err != nil {
		return nil, err
	}
	if confirmed {
		return nil, errors.New("auth: totp already confirmed")
	}
	if !t.validate(secret, code) {
		return nil, ErrTOTPBadCode
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	now := store.TimeArg(t.now())
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, t.db.Rebind(`UPDATE mfa_totp SET confirmed_at = ? WHERE user_id = ?`), now, userID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, t.db.Rebind(`DELETE FROM mfa_recovery_codes WHERE user_id = ?`), userID); err != nil {
		return nil, err
	}
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx, t.db.Rebind(`INSERT INTO mfa_recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)`),
			store.NewID(), userID, h, now); err != nil {
			return nil, err
		}
	}
	return codes, tx.Commit()
}

// Verify checks a login-time code. It accepts a TOTP code or an unused
// recovery code; a recovery code is consumed on success. The second return
// value reports whether a recovery code was used, which callers audit.
func (t *TOTP) Verify(ctx context.Context, userID, code string) (bool, error) {
	secret, confirmed, err := t.secret(ctx, userID)
	if err != nil {
		return false, err
	}
	if !confirmed {
		return false, ErrTOTPNotEnrolled
	}
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if t.validate(secret, code) {
		return false, nil
	}
	used, err := t.consumeRecovery(ctx, userID, code)
	if err != nil {
		return false, err
	}
	if used {
		return true, nil
	}
	return false, ErrTOTPBadCode
}

// Reset removes the authenticator and recovery codes. Admin action.
func (t *TOTP) Reset(ctx context.Context, userID string) error {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, t.db.Rebind(`DELETE FROM mfa_totp WHERE user_id = ?`), userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, t.db.Rebind(`DELETE FROM mfa_recovery_codes WHERE user_id = ?`), userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (t *TOTP) secret(ctx context.Context, userID string) (string, bool, error) {
	var (
		sealed    []byte
		ver       sql.NullInt64
		confirmed store.NullTime
	)
	err := t.db.QueryRowContext(ctx, t.db.Rebind(`SELECT secret_enc, key_version, confirmed_at FROM mfa_totp WHERE user_id = ?`), userID).
		Scan(&sealed, &ver, &confirmed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, ErrTOTPNotEnrolled
	}
	if err != nil {
		return "", false, err
	}
	plain, err := t.ring.Decrypt(keyring.AAD("mfa_totp", userID), sealed, int(ver.Int64))
	if err != nil {
		return "", false, err
	}
	return string(plain), confirmed.Valid, nil
}

func (t *TOTP) validate(secret, code string) bool {
	if len(code) != 6 {
		return false
	}
	ok, err := totp.ValidateCustom(code, secret, t.now().UTC(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && ok
}

func (t *TOTP) consumeRecovery(ctx context.Context, userID, code string) (bool, error) {
	code = strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	if len(code) != 10 {
		return false, nil
	}
	rows, err := t.db.QueryContext(ctx, t.db.Rebind(`SELECT id, code_hash FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL`), userID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	want := hashRecovery(code)
	matchID := ""
	for rows.Next() {
		var id, h string
		if err := rows.Scan(&id, &h); err != nil {
			return false, err
		}
		if subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 {
			matchID = id
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	if matchID == "" {
		return false, nil
	}
	res, err := t.db.ExecContext(ctx, t.db.Rebind(`UPDATE mfa_recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL`), store.TimeArg(t.now()), matchID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// Recovery codes are 10 base32 characters (50 bits), shown as XXXXX-XXXXX.
// With that much entropy a plain SHA-256 is sufficient; a slow hash would
// only slow down the legitimate user.
func newRecoveryCodes() (codes, hashes []string, err error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	for i := 0; i < recoveryCodeCount; i++ {
		raw := make([]byte, 7)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, err
		}
		c := enc.EncodeToString(raw)[:10]
		codes = append(codes, c[:5]+"-"+c[5:])
		hashes = append(hashes, hashRecovery(c))
	}
	return codes, hashes, nil
}

func hashRecovery(code string) string {
	sum := sha256.Sum256([]byte("recovery:" + code))
	return hex.EncodeToString(sum[:])
}
