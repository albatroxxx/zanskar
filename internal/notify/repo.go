// SPDX-License-Identifier: Apache-2.0

// Package notify tells people what happened (ADR 0039): it follows the audit
// log, as the SIEM export does, and sends the events each channel asked for
// to a signed webhook or by email.
package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
)

// table is where channels live, and the AAD their secrets are sealed under.
const table = "notification_channels"

// Channel kinds.
const (
	KindWebhook = "webhook"
	KindEmail   = "email"
)

// Errors the API answers with.
var (
	ErrNotFound  = errors.New("notify: channel not found")
	ErrDuplicate = errors.New("notify: a channel has that name")
)

// Config is what a channel holds that is not secret.
type Config struct {
	// WebhookHost names where a webhook goes, for the list; the URL itself,
	// which for an incoming webhook is the credential, is sealed.
	WebhookHost string `json:"webhook_host,omitempty"`
	// The email channel's SMTP server, account, sender and recipients.
	SMTPHost     string   `json:"smtp_host,omitempty"`
	SMTPPort     int      `json:"smtp_port,omitempty"`
	SMTPUsername string   `json:"smtp_username,omitempty"`
	From         string   `json:"from,omitempty"`
	To           []string `json:"to,omitempty"`
}

// Secret is what a channel holds sealed: never written to the API or a log.
type Secret struct {
	WebhookURL   string `json:"webhook_url,omitempty"`
	SigningKey   string `json:"signing_key,omitempty"`
	SMTPPassword string `json:"smtp_password,omitempty"`
}

// Channel is one destination and the kinds of event it asked for.
type Channel struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Events    []string  `json:"events"`
	Config    Config    `json:"config"`
	Enabled   bool      `json:"enabled"`
	HasSecret bool      `json:"has_secret"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	secret Secret
}

// Wants reports whether the channel asked for events of kind.
func (c *Channel) Wants(kind string) bool { return slices.Contains(c.Events, kind) }

// Repo stores channels, sealing their secrets with the key ring.
type Repo struct {
	db   *store.DB
	ring *keyring.Ring
}

// NewRepo returns a repository over db sealing secrets with ring.
func NewRepo(db *store.DB, ring *keyring.Ring) *Repo { return &Repo{db: db, ring: ring} }

const selectChannels = `SELECT id, name, kind, events, config, secret_enc, key_version, enabled, created_at, updated_at FROM notification_channels`

// List returns every channel, by name, with its secret opened for sending.
func (r *Repo) List(ctx context.Context) ([]*Channel, error) {
	rows, err := r.db.QueryContext(ctx, selectChannels+` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	type raw struct {
		c      *Channel
		sealed []byte
		ver    sql.NullInt64
	}
	var all []raw
	for rows.Next() {
		c, sealed, ver, err := scan(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		all = append(all, raw{c, sealed, ver})
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Opened after the cursor is closed: unsealing reads the key ring, and
	// SQLite runs on one connection.
	out := make([]*Channel, 0, len(all))
	for _, a := range all {
		if err := r.open(ctx, a.c, a.sealed, a.ver); err != nil {
			return nil, err
		}
		out = append(out, a.c)
	}
	return out, nil
}

// Get returns one channel with its secret opened, or ErrNotFound.
func (r *Repo) Get(ctx context.Context, id string) (*Channel, error) {
	c, sealed, ver, err := scan(r.db.QueryRowContext(ctx, r.db.Rebind(selectChannels+` WHERE id = ?`), id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return c, r.open(ctx, c, sealed, ver)
}

func scan(sc store.Scanner) (*Channel, []byte, sql.NullInt64, error) {
	var (
		c                Channel
		events, config   string
		sealed           []byte
		ver              sql.NullInt64
		created, updated store.NullTime
	)
	if err := sc.Scan(&c.ID, &c.Name, &c.Kind, &events, &config, &sealed, &ver, &c.Enabled, &created, &updated); err != nil {
		return nil, nil, ver, err
	}
	if err := json.Unmarshal([]byte(events), &c.Events); err != nil {
		return nil, nil, ver, fmt.Errorf("notify: channel %s events: %w", c.ID, err)
	}
	if err := json.Unmarshal([]byte(config), &c.Config); err != nil {
		return nil, nil, ver, fmt.Errorf("notify: channel %s config: %w", c.ID, err)
	}
	c.CreatedAt, c.UpdatedAt = created.Time, updated.Time
	return &c, sealed, ver, nil
}

func (r *Repo) open(_ context.Context, c *Channel, sealed []byte, ver sql.NullInt64) error {
	if len(sealed) == 0 || !ver.Valid {
		return nil
	}
	plain, err := r.ring.Decrypt(keyring.AAD(table, c.ID), sealed, int(ver.Int64))
	if err != nil {
		return fmt.Errorf("notify: unseal channel %s: %w", c.ID, err)
	}
	if err := json.Unmarshal(plain, &c.secret); err != nil {
		return fmt.Errorf("notify: channel %s secret: %w", c.ID, err)
	}
	c.HasSecret = true
	return nil
}

// Create stores a new channel with its secret; ID and the times are set.
func (r *Repo) Create(ctx context.Context, c *Channel, s Secret) error {
	c.ID = store.NewID()
	now := time.Now().UTC()
	c.CreatedAt, c.UpdatedAt = now, now
	sealed, ver, err := r.seal(c.ID, s)
	if err != nil {
		return err
	}
	events, config, err := marshal(c)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO notification_channels (id, name, kind, events, config, secret_enc, key_version, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		c.ID, c.Name, c.Kind, events, config, sealed, ver, c.Enabled, store.TimeArg(now), store.TimeArg(now))
	if store.IsUniqueViolation(err) {
		return ErrDuplicate
	}
	if err != nil {
		return err
	}
	c.secret, c.HasSecret = s, sealed != nil
	return nil
}

// Update rewrites a channel's settings and its secret.
func (r *Repo) Update(ctx context.Context, c *Channel, s Secret) error {
	c.UpdatedAt = time.Now().UTC()
	sealed, ver, err := r.seal(c.ID, s)
	if err != nil {
		return err
	}
	events, config, err := marshal(c)
	if err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE notification_channels SET name = ?, events = ?, config = ?, secret_enc = ?, key_version = ?, enabled = ?, updated_at = ? WHERE id = ?`),
		c.Name, events, config, sealed, ver, c.Enabled, store.TimeArg(c.UpdatedAt), c.ID)
	if store.IsUniqueViolation(err) {
		return ErrDuplicate
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	c.secret, c.HasSecret = s, sealed != nil
	return nil
}

// Delete removes a channel; its checkpoint goes with it.
func (r *Repo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM notification_channels WHERE id = ?`), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, err = r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM audit_export_state WHERE sink = ?`), Sink(id))
	return err
}

// Sink is a channel's checkpoint name in audit_export_state.
func Sink(id string) string { return "notify:" + id }

func (r *Repo) seal(id string, s Secret) ([]byte, sql.NullInt64, error) {
	if s == (Secret{}) {
		return nil, sql.NullInt64{}, nil
	}
	plain, err := json.Marshal(s)
	if err != nil {
		return nil, sql.NullInt64{}, err
	}
	sealed, ver, err := r.ring.Encrypt(keyring.AAD(table, id), plain)
	if err != nil {
		return nil, sql.NullInt64{}, err
	}
	return sealed, sql.NullInt64{Int64: int64(ver), Valid: true}, nil
}

func marshal(c *Channel) (string, string, error) {
	if c.Events == nil {
		c.Events = []string{}
	}
	events, err := json.Marshal(c.Events)
	if err != nil {
		return "", "", err
	}
	config, err := json.Marshal(c.Config)
	return string(events), string(config), err
}
