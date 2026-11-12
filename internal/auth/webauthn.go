// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Security key errors.
var (
	// ErrKeysOff: keys cannot work at this gateway's address (no
	// ZANSKAR_PUBLIC_URL, or an IP address); Keys.Off says why.
	ErrKeysOff = errors.New("auth: security keys are off at this address")
	// ErrNoKeys: the account has no key to ask for.
	ErrNoKeys = errors.New("auth: no security key registered")
	// ErrKeyBad: the browser's answer did not verify. It counts as a wrong
	// code wherever a code would.
	ErrKeyBad = errors.New("auth: security key not accepted")
	// ErrKeyCloned: the key's signature counter went back, so a copy of it may
	// exist. Refused, counted and audited as such; the stored counter stays.
	ErrKeyCloned = fmt.Errorf("%w: its counter went back", ErrKeyBad)
	// ErrNoCeremony: no challenge is waiting for this session and purpose, or
	// it expired. Not a wrong answer: the browser starts again.
	ErrNoCeremony  = errors.New("auth: no security key request is waiting; start again")
	ErrTooManyKeys = errors.New("auth: too many security keys")
	ErrKeyNotFound = errors.New("auth: no such security key")
	ErrKeyName     = errors.New("auth: a key's name is 1 to 64 characters")
)

// What a key proves, each a ceremony of its own: a challenge begun for one
// cannot finish another.
const (
	PurposeRegister = "register"
	PurposeSignIn   = "sign_in"
	PurposeStepUp   = "step_up"
	PurposeCLI      = "cli"
)

const (
	// maxKeys a person may register (ADR 0028).
	maxKeys = 10
	// ceremonyTTL is how long a challenge waits for its answer, once.
	ceremonyTTL = 2 * time.Minute
	// maxKeyName is a key's name in characters.
	maxKeyName = 64
)

// Key is one registered security key or passkey as the console shows it.
type Key struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	// Synced is a passkey a password manager or platform keeps in sync
	// between devices (its backup state).
	Synced bool `json:"synced"`
}

// Keys stores the security keys and passkeys of every account and runs
// their ceremonies (ADR 0028). Verification is go-webauthn's. A challenge
// lives in memory for ceremonyTTL, belongs to one session and one purpose,
// and is used once.
type Keys struct {
	db  *store.DB
	wa  *webauthn.WebAuthn
	off string
	now func() time.Time

	mu         sync.Mutex
	ceremonies map[string]ceremony
}

type ceremony struct {
	data    webauthn.SessionData
	expires time.Time
}

// NewKeys returns the store. publicURL is ZANSKAR_PUBLIC_URL: its host is
// the relying party id and its origin the one every signature must name.
// With no public address, or an IP address for one, keys are off and Off
// says why; the store still lists and removes keys registered before.
func NewKeys(db *store.DB, publicURL, displayName string) *Keys {
	k := &Keys{db: db, now: time.Now, ceremonies: map[string]ceremony{}}
	if publicURL == "" {
		k.off = "No public address is set (ZANSKAR_PUBLIC_URL)."
		return k
	}
	u, err := url.Parse(publicURL)
	if err != nil || u.Hostname() == "" {
		k.off = "The public address cannot be read."
		return k
	}
	if net.ParseIP(u.Hostname()) != nil {
		k.off = "The public address is an IP address; keys need a host name."
		return k
	}
	return k.withOrigin(strings.TrimRight(publicURL, "/"), u.Hostname(), displayName)
}

// withOrigin configures the relying party for one origin and its host.
func (k *Keys) withOrigin(origin, rpID, displayName string) *Keys {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: displayName,
		RPOrigins:     []string{origin},
		// Who made the key is not asked: any key or passkey works, and no
		// device details are collected.
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// A PIN or fingerprint is used where the key has one; the
			// password was the first factor already.
			UserVerification: protocol.VerificationPreferred,
			ResidentKey:      protocol.ResidentKeyRequirementDiscouraged,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTTL, TimeoutUVD: ceremonyTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTTL, TimeoutUVD: ceremonyTTL},
		},
	})
	if err != nil {
		k.off = "The public address cannot be used for keys."
		return k
	}
	k.wa = wa
	return k
}

// Off is why keys cannot work at this address, or "" when they can.
func (k *Keys) Off() string { return k.off }

// Count is how many keys an account has.
func (k *Keys) Count(ctx context.Context, userID string) (int, error) {
	var n int
	err := k.db.QueryRowContext(ctx, k.db.Rebind(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`), userID).Scan(&n)
	return n, err
}

// List is an account's keys, the oldest first.
func (k *Keys) List(ctx context.Context, userID string) ([]Key, error) {
	rows, err := k.db.QueryContext(ctx, k.db.Rebind(
		`SELECT id, name, backup_state, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at, id`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Key{}
	for rows.Next() {
		var (
			key     Key
			created store.NullTime
			used    store.NullTime
		)
		if err := rows.Scan(&key.ID, &key.Name, &key.Synced, &created, &used); err != nil {
			return nil, err
		}
		key.CreatedAt = created.Time
		if used.Valid {
			t := used.Time
			key.LastUsedAt = &t
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

// Rename names one of an account's keys again.
func (k *Keys) Rename(ctx context.Context, userID, id, name string) error {
	name, err := keyName(name)
	if err != nil {
		return err
	}
	res, err := k.db.ExecContext(ctx, k.db.Rebind(`UPDATE webauthn_credentials SET name = ? WHERE id = ? AND user_id = ?`), name, id, userID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrKeyNotFound
	}
	return nil
}

// keyName is a key's name trimmed, or ErrKeyName.
func keyName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxKeyName || strings.ContainsFunc(name, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return "", ErrKeyName
	}
	return name, nil
}

// keyUser is an account as go-webauthn sees it. Its handle is the account's
// id, which names nobody.
type keyUser struct {
	id, name, display string
	creds             []webauthn.Credential
}

func (u keyUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u keyUser) WebAuthnName() string                       { return u.name }
func (u keyUser) WebAuthnDisplayName() string                { return u.display }
func (u keyUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// credentials are an account's keys as go-webauthn reads them, and the row
// id of each by its credential id.
func (k *Keys) credentials(ctx context.Context, userID string) ([]webauthn.Credential, map[string]string, error) {
	rows, err := k.db.QueryContext(ctx, k.db.Rebind(
		`SELECT id, credential_id, public_key, sign_count, aaguid, transports, backup_eligible, backup_state, user_verified, attestation_type
		 FROM webauthn_credentials WHERE user_id = ?`), userID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var creds []webauthn.Credential
	ids := map[string]string{}
	for rows.Next() {
		var (
			id, transports, attType string
			c                       webauthn.Credential
			count                   int64
		)
		if err := rows.Scan(&id, &c.ID, &c.PublicKey, &count, &c.Authenticator.AAGUID, &transports,
			&c.Flags.BackupEligible, &c.Flags.BackupState, &c.Flags.UserVerified, &attType); err != nil {
			return nil, nil, err
		}
		c.Authenticator.SignCount = uint32(count) //nolint:gosec // stored from a uint32
		c.AttestationType = attType
		c.Flags.UserPresent = true
		for t := range strings.SplitSeq(transports, ",") {
			if t != "" {
				c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
			}
		}
		creds = append(creds, c)
		ids[string(c.ID)] = id
	}
	return creds, ids, rows.Err()
}

func ceremonyKey(sessionID, purpose string) string { return sessionID + "\x00" + purpose }

// keep holds a challenge for the session and purpose, replacing one begun
// before, and drops those that expired.
func (k *Keys) keep(sessionID, purpose string, data *webauthn.SessionData) {
	now := k.now()
	k.mu.Lock()
	defer k.mu.Unlock()
	for key, c := range k.ceremonies {
		if now.After(c.expires) {
			delete(k.ceremonies, key)
		}
	}
	k.ceremonies[ceremonyKey(sessionID, purpose)] = ceremony{data: *data, expires: now.Add(ceremonyTTL)}
}

// take returns the session's challenge for purpose, once.
func (k *Keys) take(sessionID, purpose string) (webauthn.SessionData, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	key := ceremonyKey(sessionID, purpose)
	c, ok := k.ceremonies[key]
	delete(k.ceremonies, key)
	if !ok || k.now().After(c.expires) {
		return webauthn.SessionData{}, ErrNoCeremony
	}
	return c.data, nil
}

// Forget drops whatever challenges a session has waiting, as it ends.
func (k *Keys) Forget(sessionID string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, p := range []string{PurposeRegister, PurposeSignIn, PurposeStepUp, PurposeCLI} {
		delete(k.ceremonies, ceremonyKey(sessionID, p))
	}
}

// BeginRegistration returns the options the browser creates a key with. A
// key the account has already is excluded, so it cannot be added twice.
func (k *Keys) BeginRegistration(ctx context.Context, sessionID string, u *user.User) (*protocol.CredentialCreation, error) {
	if k.wa == nil {
		return nil, ErrKeysOff
	}
	creds, _, err := k.credentials(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if len(creds) >= maxKeys {
		return nil, ErrTooManyKeys
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		exclude = append(exclude, c.Descriptor())
	}
	creation, data, err := k.wa.BeginRegistration(keyUser{id: u.ID, name: u.Username, display: displayName(u), creds: creds},
		webauthn.WithExclusions(exclude))
	if err != nil {
		return nil, err
	}
	k.keep(sessionID, PurposeRegister, data)
	return creation, nil
}

// verifyRegistration checks the browser's answer to BeginRegistration and
// returns the new credential, not yet stored.
func (k *Keys) verifyRegistration(ctx context.Context, sessionID string, u *user.User, body []byte) (*webauthn.Credential, error) {
	if k.wa == nil {
		return nil, ErrKeysOff
	}
	data, err := k.take(sessionID, PurposeRegister)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyBad, err)
	}
	creds, _, err := k.credentials(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	cred, err := k.wa.CreateCredential(keyUser{id: u.ID, name: u.Username, display: displayName(u), creds: creds}, data, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyBad, err)
	}
	return cred, nil
}

// insert stores a verified credential under name in tx, refusing past
// maxKeys.
func (k *Keys) insert(ctx context.Context, tx *sql.Tx, userID, name string, cred *webauthn.Credential) (*Key, error) {
	var n int
	if err := tx.QueryRowContext(ctx, k.db.Rebind(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`), userID).Scan(&n); err != nil {
		return nil, err
	}
	if n >= maxKeys {
		return nil, ErrTooManyKeys
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	now := k.now()
	key := &Key{ID: store.NewID(), Name: name, CreatedAt: now, Synced: cred.Flags.BackupState}
	if _, err := tx.ExecContext(ctx, k.db.Rebind(
		`INSERT INTO webauthn_credentials (id, user_id, name, credential_id, public_key, sign_count, aaguid, transports,
		 backup_eligible, backup_state, user_verified, attestation_type, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		key.ID, userID, name, cred.ID, cred.PublicKey, int64(cred.Authenticator.SignCount), cred.Authenticator.AAGUID, strings.Join(transports, ","),
		cred.Flags.BackupEligible, cred.Flags.BackupState, cred.Flags.UserVerified, cred.AttestationType, store.TimeArg(now)); err != nil {
		return nil, err
	}
	return key, nil
}

// BeginAssertion returns the options the browser asks the account's keys
// with, for purpose.
func (k *Keys) BeginAssertion(ctx context.Context, sessionID, userID, purpose string) (*protocol.CredentialAssertion, error) {
	if k.wa == nil {
		return nil, ErrKeysOff
	}
	creds, _, err := k.credentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, ErrNoKeys
	}
	assertion, data, err := k.wa.BeginLogin(keyUser{id: userID, creds: creds})
	if err != nil {
		return nil, err
	}
	k.keep(sessionID, purpose, data)
	return assertion, nil
}

// FinishAssertion checks the browser's answer to BeginAssertion for the same
// session and purpose. A key whose counter went back is refused with
// ErrKeyCloned and its stored counter kept; an accepted one has its counter,
// flags and last use written. It returns the key that answered.
func (k *Keys) FinishAssertion(ctx context.Context, sessionID, userID, purpose string, body []byte) (*Key, error) {
	if k.wa == nil {
		return nil, ErrKeysOff
	}
	data, err := k.take(sessionID, purpose)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyBad, err)
	}
	creds, ids, err := k.credentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	cred, err := k.wa.ValidateLogin(keyUser{id: userID, creds: creds}, data, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyBad, err)
	}
	id := ids[string(cred.ID)]
	if cred.Authenticator.CloneWarning {
		return &Key{ID: id}, ErrKeyCloned
	}
	now := k.now()
	if _, err := k.db.ExecContext(ctx, k.db.Rebind(
		`UPDATE webauthn_credentials SET sign_count = ?, backup_state = ?, user_verified = ?, last_used_at = ? WHERE id = ? AND user_id = ?`),
		int64(cred.Authenticator.SignCount), cred.Flags.BackupState, cred.Flags.UserVerified, store.TimeArg(now), id, userID); err != nil {
		return nil, err
	}
	var name string
	if err := k.db.QueryRowContext(ctx, k.db.Rebind(`SELECT name FROM webauthn_credentials WHERE id = ?`), id).Scan(&name); err != nil {
		return nil, err
	}
	return &Key{ID: id, Name: name, LastUsedAt: &now, Synced: cred.Flags.BackupState}, nil
}

// displayName is what an authenticator shows for the account.
func displayName(u *user.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Username
}
