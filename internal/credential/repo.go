// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
)

const table = "credentials"

// Vault stores credentials with their secrets sealed by the key ring.
type Vault struct {
	db   *store.DB
	ring *keyring.Ring
}

// NewVault returns a vault over db sealing with ring.
func NewVault(db *store.DB, ring *keyring.Ring) *Vault {
	return &Vault{db: db, ring: ring}
}

const cols = `id, name, type, mode, username, domain, public_key, key_version, created_by,
	created_at, updated_at, rotated_at, secret_enc IS NOT NULL,
	(SELECT COUNT(*) FROM target_credentials tc WHERE tc.credential_id = credentials.id),
	(SELECT COUNT(*) FROM asg_credentials ac WHERE ac.credential_id = credentials.id)`

// Create validates, seals the secret and inserts. c.ID and timestamps are set.
func (v *Vault) Create(ctx context.Context, c *Credential, s *Secret, createdBy string) error {
	p, err := validateAndPrepare(c, s)
	if err != nil {
		return err
	}
	defer crypto.Zero(p.plaintext)
	c.ID = store.NewID()
	now := time.Now().UTC()
	c.CreatedAt, c.UpdatedAt, c.CreatedBy, c.RotatedAt = now, now, createdBy, nil

	var sealed []byte
	var keyVersion any
	if len(p.plaintext) > 0 {
		var ver int
		sealed, ver, err = v.ring.Encrypt(keyring.AAD(table, c.ID), p.plaintext)
		if err != nil {
			return err
		}
		keyVersion = ver
		c.KeyVersion, c.HasSecret = ver, true
	}
	_, err = v.db.ExecContext(ctx, v.db.Rebind(`INSERT INTO credentials
		(id, name, type, mode, username, domain, secret_enc, public_key, key_version, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		c.ID, c.Name, string(c.Type), string(c.Mode), nullStr(c.Username), nullStr(c.Domain),
		sealed, nullStr(c.PublicKey), keyVersion, nullStr(createdBy), store.TimeArg(now), store.TimeArg(now))
	if err != nil {
		if isUnique(err) {
			return ErrDuplicate
		}
		return err
	}
	return nil
}

// Get returns metadata only.
func (v *Vault) Get(ctx context.Context, id string) (*Credential, error) {
	row := v.db.QueryRowContext(ctx, v.db.Rebind(`SELECT `+cols+` FROM credentials WHERE id = ?`), id)
	return scan(row)
}

// List returns credentials ordered by name after the given name.
func (v *Vault) List(ctx context.Context, afterName string, limit int) ([]*Credential, string, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := v.db.QueryContext(ctx, v.db.Rebind(`SELECT `+cols+` FROM credentials WHERE name > ? ORDER BY name LIMIT ?`), afterName, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []*Credential
	for rows.Next() {
		c, err := scan(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].Name
	}
	if out == nil {
		out = []*Credential{}
	}
	return out, next, nil
}

// Update changes metadata only. Type and mode are immutable; use Rotate for
// the secret.
func (v *Vault) Update(ctx context.Context, id, name, username, domain string) (*Credential, error) {
	c, err := v.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	c.Name, c.Username, c.Domain = name, username, domain
	// Re-run the type rules against the current secret state: a vaulted
	// password credential must keep a username, and so on.
	if c.Mode == ModeVaulted && c.Type != TypeSSHCA && strings.TrimSpace(username) == "" {
		return nil, fmt.Errorf("%w: username required", ErrInvalid)
	}
	if c.Type == TypeDomain && strings.TrimSpace(domain) == "" {
		return nil, fmt.Errorf("%w: domain required", ErrInvalid)
	}
	if strings.TrimSpace(name) == "" || len(name) > 255 {
		return nil, fmt.Errorf("%w: name required (1-255 characters)", ErrInvalid)
	}
	if c.Mode != ModeVaulted {
		username = ""
	}
	res, err := v.db.ExecContext(ctx, v.db.Rebind(`UPDATE credentials SET name = ?, username = ?, domain = ?, updated_at = ? WHERE id = ?`),
		strings.TrimSpace(name), nullStr(strings.TrimSpace(username)), nullStr(strings.TrimSpace(domain)), store.TimeArg(time.Now()), id)
	if err != nil {
		if isUnique(err) {
			return nil, ErrDuplicate
		}
		return nil, err
	}
	if err := affected(res); err != nil {
		return nil, err
	}
	return v.Get(ctx, id)
}

// Rotate replaces the secret, re-derives the public key and stamps rotated_at.
func (v *Vault) Rotate(ctx context.Context, id string, s *Secret) (*Credential, error) {
	c, err := v.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if c.Mode != ModeVaulted || c.Type == TypeEC2InstanceConnect {
		return nil, fmt.Errorf("%w: nothing to rotate for %s/%s", ErrInvalid, c.Type, c.Mode)
	}
	p, err := validateAndPrepare(c, s)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(p.plaintext)
	sealed, ver, err := v.ring.Encrypt(keyring.AAD(table, id), p.plaintext)
	if err != nil {
		return nil, err
	}
	now := store.TimeArg(time.Now())
	res, err := v.db.ExecContext(ctx, v.db.Rebind(`UPDATE credentials SET secret_enc = ?, public_key = ?, key_version = ?, rotated_at = ?, updated_at = ? WHERE id = ?`),
		sealed, nullStr(c.PublicKey), ver, now, now, id)
	if err != nil {
		return nil, err
	}
	if err := affected(res); err != nil {
		return nil, err
	}
	return v.Get(ctx, id)
}

// Delete removes a credential that nothing references.
func (v *Vault) Delete(ctx context.Context, id string) error {
	c, err := v.Get(ctx, id)
	if err != nil {
		return err
	}
	if c.InUseBy.Targets > 0 || c.InUseBy.AutoscalingGroups > 0 {
		return ErrInUse
	}
	res, err := v.db.ExecContext(ctx, v.db.Rebind(`DELETE FROM credentials WHERE id = ?`), id)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "foreign key") {
			return ErrInUse
		}
		return err
	}
	return affected(res)
}

// Opened is a credential with its secret in memory. Only the gateway calls
// Open, right before connecting, and must Close when the handshake is done.
type Opened struct {
	Credential
	Password   string
	PrivateKey []byte // OpenSSH PEM, unencrypted
}

// Close zeroes the secret material (best effort; see crypto.Zero).
func (o *Opened) Close() {
	crypto.Zero(o.PrivateKey)
	b := []byte(o.Password)
	crypto.Zero(b)
	o.Password, o.PrivateKey = "", nil
}

// Open unseals the secret. It fails for modes that store nothing.
func (v *Vault) Open(ctx context.Context, id string) (*Opened, error) {
	c, err := v.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !c.HasSecret {
		return nil, ErrNoSecret
	}
	var sealed []byte
	var ver sql.NullInt64
	if err := v.db.QueryRowContext(ctx, v.db.Rebind(`SELECT secret_enc, key_version FROM credentials WHERE id = ?`), id).Scan(&sealed, &ver); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	plain, err := v.ring.Decrypt(keyring.AAD(table, id), sealed, int(ver.Int64))
	if err != nil {
		return nil, fmt.Errorf("credential %s: unseal: %w", id, err)
	}
	o := &Opened{Credential: *c}
	switch c.Type {
	case TypeSSHKey, TypeSSHCA:
		o.PrivateKey = plain
	default:
		o.Password = string(plain)
		crypto.Zero(plain)
	}
	return o, nil
}

type scanner interface{ Scan(dest ...any) error }

func scan(s scanner) (*Credential, error) {
	var (
		c                         Credential
		typ, mode                 string
		username, domain, pub, by sql.NullString
		keyVersion                sql.NullInt64
		created, updated, rotated store.NullTime
		hasSecret                 bool
	)
	err := s.Scan(&c.ID, &c.Name, &typ, &mode, &username, &domain, &pub, &keyVersion, &by,
		&created, &updated, &rotated, &hasSecret, &c.InUseBy.Targets, &c.InUseBy.AutoscalingGroups)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	c.Type, c.Mode = Type(typ), Mode(mode)
	c.Username, c.Domain, c.PublicKey, c.CreatedBy = username.String, domain.String, pub.String, by.String
	c.KeyVersion, c.HasSecret = int(keyVersion.Int64), hasSecret
	c.CreatedAt, c.UpdatedAt, c.RotatedAt = created.Time, updated.Time, rotated.Ptr()
	return &c, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func affected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func isUnique(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate key")
}
