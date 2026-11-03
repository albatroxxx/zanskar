// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
)

// Server is the mail server every email channel sends through (ADR 0039,
// amended 2026-11-03, later): set once under Settings › Notifications, its
// password sealed with the key ring and never written to the API or a log.
// A channel keeps its recipients alone.
type Server struct {
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Username    string    `json:"username"`
	From        string    `json:"from"`
	HasPassword bool      `json:"has_password"`
	UpdatedAt   time.Time `json:"updated_at"`
	password    string
}

// serverTable is where the one mail server lives, and the AAD its password
// is sealed under (with "1", its only row).
const serverTable = "email_server"

// Server returns the mail server with its password opened for sending, or
// nil when none is set.
func (r *Repo) Server(ctx context.Context) (*Server, error) {
	var (
		s       Server
		sealed  []byte
		ver     sql.NullInt64
		updated store.NullTime
	)
	err := r.db.QueryRowContext(ctx, `SELECT host, port, username, from_address, password_enc, key_version, updated_at FROM email_server WHERE id = 1`).
		Scan(&s.Host, &s.Port, &s.Username, &s.From, &sealed, &ver, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.UpdatedAt = updated.Time
	if len(sealed) > 0 && ver.Valid {
		plain, err := r.ring.Decrypt(keyring.AAD(serverTable, "1"), sealed, int(ver.Int64))
		if err != nil {
			return nil, fmt.Errorf("notify: unseal the mail server's password: %w", err)
		}
		s.password, s.HasPassword = string(plain), true
	}
	return &s, nil
}

// SetServer stores the mail server with password sealed; an empty password
// stores none. s comes back with its time and whether a password is held.
func (r *Repo) SetServer(ctx context.Context, s *Server, password string) error {
	var sealed []byte
	var ver sql.NullInt64
	if password != "" {
		b, v, err := r.ring.Encrypt(keyring.AAD(serverTable, "1"), []byte(password))
		if err != nil {
			return err
		}
		sealed, ver = b, sql.NullInt64{Int64: int64(v), Valid: true}
	}
	now := time.Now().UTC()
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO email_server (id, host, port, username, from_address, password_enc, key_version, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET host = excluded.host, port = excluded.port, username = excluded.username, from_address = excluded.from_address,
		password_enc = excluded.password_enc, key_version = excluded.key_version, updated_at = excluded.updated_at`),
		s.Host, s.Port, s.Username, s.From, sealed, ver, store.TimeArg(now))
	if err != nil {
		return err
	}
	s.UpdatedAt, s.HasPassword, s.password = now, password != "", password
	return nil
}

// ClearServer forgets the mail server; email channels then send nothing
// until one is set again.
func (r *Repo) ClearServer(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM email_server WHERE id = 1`)
	return err
}

// AdoptServer makes the mail server from the first email channel that
// carries its own (from before 2026-11-03, when each channel did), when none
// is set yet, and takes the server out of every email channel, which keeps
// its recipients. It returns the server adopted, or nil when there was
// nothing to adopt. The gateway runs it once at start.
func (r *Repo) AdoptServer(ctx context.Context) (*Server, error) {
	if s, err := r.Server(ctx); err != nil || s != nil {
		return nil, err
	}
	channels, err := r.List(ctx)
	if err != nil {
		return nil, err
	}
	var adopted *Server
	for _, c := range channels {
		if c.Kind != KindEmail || c.Config.SMTPHost == "" {
			continue
		}
		if adopted == nil {
			adopted = &Server{Host: c.Config.SMTPHost, Port: c.Config.SMTPPort, Username: c.Config.SMTPUsername, From: c.Config.From}
			if err := r.SetServer(ctx, adopted, c.secret.SMTPPassword); err != nil {
				return nil, err
			}
		}
		c.Config = Config{To: c.Config.To}
		s := c.secret
		s.SMTPPassword = ""
		if err := r.Update(ctx, c, s); err != nil {
			return nil, err
		}
	}
	return adopted, nil
}
