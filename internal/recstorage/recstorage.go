// SPDX-License-Identifier: Apache-2.0

// Package recstorage lets an administrator move recording storage to an
// S3-compatible bucket from the console and back (ADR 0020, QA finding
// R18). The configuration is one sealed row; the active backend is swapped
// in place on the recording router, so the next session records to the new
// place with no restart. A configuration is only saved after a probe wrote,
// read back and deleted an object with it, because a session whose upload
// fails still leaves a recording row behind. Precedence: console row, then
// the environment's ZANSKAR_RECORDINGS_S3_* variables, then the local
// directory.
package recstorage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/store"
)

// Sources of the active backend.
const (
	SourceConsole     = "console"
	SourceEnvironment = "environment"
	SourceLocal       = "local"
)

// Auth modes.
const (
	AuthRole = "role" // the SDK's default chain: instance role, environment, shared config
	AuthKeys = "keys" // a static access key, secret sealed by the key ring
)

const table = "recording_storage"

// Errors.
var (
	ErrInvalid = errors.New("recstorage: invalid configuration")
	ErrBusy    = errors.New("recstorage: a move is already running")
)

var bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// Config is an S3 backend as the console edits it. The secret is never
// returned by the API; SecretSet says whether one is stored.
type Config struct {
	Bucket          string `json:"bucket"`
	Prefix          string `json:"prefix"`
	Region          string `json:"region,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	KMSKeyID        string `json:"kms_key_id,omitempty"`
	Auth            string `json:"auth"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	SecretSet       bool   `json:"secret_set,omitempty"`
}

// Validate normalises and checks a configuration.
func (c *Config) Validate() error {
	c.Bucket = strings.TrimSpace(c.Bucket)
	if !bucketRe.MatchString(c.Bucket) {
		return fmt.Errorf("%w: bucket name %q is not valid", ErrInvalid, c.Bucket)
	}
	c.Prefix = strings.Trim(strings.TrimSpace(c.Prefix), "/")
	if c.Prefix == "" {
		c.Prefix = "recordings"
	}
	if strings.Contains(c.Prefix, "..") || strings.ContainsAny(c.Prefix, " \t\n\r\\") {
		return fmt.Errorf("%w: prefix must be a plain object key prefix", ErrInvalid)
	}
	c.Prefix += "/"
	c.Region = strings.TrimSpace(c.Region)
	c.Endpoint = strings.TrimSpace(c.Endpoint)
	if c.Endpoint != "" {
		u, err := url.Parse(c.Endpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%w: endpoint must be an http(s) URL", ErrInvalid)
		}
	}
	c.KMSKeyID = strings.TrimSpace(c.KMSKeyID)
	c.AccessKeyID = strings.TrimSpace(c.AccessKeyID)
	switch c.Auth {
	case "", AuthRole:
		c.Auth = AuthRole
		c.AccessKeyID, c.SecretAccessKey = "", ""
	case AuthKeys:
		if c.AccessKeyID == "" || c.SecretAccessKey == "" {
			return fmt.Errorf("%w: auth keys needs access_key_id and secret_access_key", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: auth must be role or keys", ErrInvalid)
	}
	return nil
}

// Public is the configuration without its secret, the access key id
// shortened to its last four characters.
func (c Config) Public() Config {
	c.SecretSet = c.SecretAccessKey != ""
	c.SecretAccessKey = ""
	if len(c.AccessKeyID) > 4 {
		c.AccessKeyID = "…" + c.AccessKeyID[len(c.AccessKeyID)-4:]
	}
	return c
}

func (c Config) options(spool string) recording.S3Options {
	return recording.S3Options{Bucket: c.Bucket, Prefix: c.Prefix, Region: c.Region, Endpoint: c.Endpoint, KMSKeyID: c.KMSKeyID,
		SpoolDir: spool, AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey}
}

// Repo stores the console row.
type Repo struct {
	db   *store.DB
	ring *keyring.Ring
}

// NewRepo returns a repository over db sealing secrets with ring.
func NewRepo(db *store.DB, ring *keyring.Ring) *Repo { return &Repo{db: db, ring: ring} }

// Get returns the console configuration, or nil when none is stored.
func (r *Repo) Get(ctx context.Context) (*Config, error) {
	var c Config
	var sealed []byte
	var ver sql.NullInt64
	err := r.db.QueryRowContext(ctx, `SELECT bucket, prefix, region, endpoint, kms_key_id, auth, access_key_id, secret_enc, key_version FROM recording_storage WHERE id = 'active'`).
		Scan(&c.Bucket, &c.Prefix, &c.Region, &c.Endpoint, &c.KMSKeyID, &c.Auth, &c.AccessKeyID, &sealed, &ver)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(sealed) > 0 {
		plain, err := r.ring.Decrypt(keyring.AAD(table, "active"), sealed, int(ver.Int64))
		if err != nil {
			return nil, fmt.Errorf("recstorage: unseal secret: %w", err)
		}
		c.SecretAccessKey = string(plain)
	}
	return &c, nil
}

// Put stores (or replaces) the console configuration.
func (r *Repo) Put(ctx context.Context, c Config, by string) error {
	var sealed []byte
	var ver sql.NullInt64
	if c.SecretAccessKey != "" {
		b, v, err := r.ring.Encrypt(keyring.AAD(table, "active"), []byte(c.SecretAccessKey))
		if err != nil {
			return err
		}
		sealed, ver = b, sql.NullInt64{Int64: int64(v), Valid: true}
	}
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO recording_storage (id, bucket, prefix, region, endpoint, kms_key_id, auth, access_key_id, secret_enc, key_version, updated_by, updated_at)
		VALUES ('active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET bucket = excluded.bucket, prefix = excluded.prefix, region = excluded.region, endpoint = excluded.endpoint, kms_key_id = excluded.kms_key_id,
		auth = excluded.auth, access_key_id = excluded.access_key_id, secret_enc = excluded.secret_enc, key_version = excluded.key_version, updated_by = excluded.updated_by, updated_at = excluded.updated_at`),
		c.Bucket, c.Prefix, c.Region, c.Endpoint, c.KMSKeyID, c.Auth, c.AccessKeyID, sealed, ver, sql.NullString{String: by, Valid: by != ""}, store.TimeArg(time.Now().UTC()))
	return err
}

// Delete removes the console configuration.
func (r *Repo) Delete(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM recording_storage WHERE id = 'active'`)
	return err
}

// Move is the state of a move of local recordings to the bucket.
type Move struct {
	Running    bool       `json:"running"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Moved      int        `json:"moved"`
	Failed     int        `json:"failed"`
	Total      int        `json:"total"`
	LastError  string     `json:"last_error,omitempty"`
}

// Manager resolves and swaps the active backend.
type Manager struct {
	Repo     *Repo
	Router   *recording.Router
	Sessions *session.Repo
	// Env is the environment's configuration, nil when none.
	Env *Config
	// SpoolDir is where in-progress uploads are spooled.
	SpoolDir string
	// Build makes the backend; tests inject one over a fake client.
	Build func(ctx context.Context, o recording.S3Options) (*recording.S3Storage, error)
	Log   *slog.Logger

	mu     sync.Mutex
	source string
	active *Config
	move   Move
}

func (m *Manager) build(ctx context.Context, c Config) (*recording.S3Storage, error) {
	if m.Build == nil {
		m.Build = recording.NewS3Storage
	}
	return m.Build(ctx, c.options(m.SpoolDir))
}

// Load resolves the backend at start. A console or environment
// configuration that cannot be built is an error: recordings must not
// quietly go somewhere the audit trail does not say.
func (m *Manager) Load(ctx context.Context) error {
	if m.Log == nil {
		m.Log = slog.Default()
	}
	c, err := m.Repo.Get(ctx)
	if err != nil {
		return err
	}
	switch {
	case c != nil:
		s, err := m.build(ctx, *c)
		if err != nil {
			return fmt.Errorf("recstorage: console configuration: %w", err)
		}
		m.set(SourceConsole, c, s)
	case m.Env != nil:
		s, err := m.build(ctx, *m.Env)
		if err != nil {
			return fmt.Errorf("recstorage: environment configuration: %w", err)
		}
		m.set(SourceEnvironment, m.Env, s)
	default:
		m.set(SourceLocal, nil, nil)
	}
	return nil
}

func (m *Manager) set(source string, c *Config, s *recording.S3Storage) {
	m.mu.Lock()
	m.source, m.active = source, c
	m.mu.Unlock()
	m.Router.SetS3(s)
}

// Source says where the active backend came from.
func (m *Manager) Source() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.source
}

// Active returns the active configuration without its secret, nil for local.
func (m *Manager) Active() *Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return nil
	}
	p := m.active.Public()
	return &p
}

// probe writes, reads back and deletes an object with s, the same path a
// session takes, so a bad bucket, key, policy or KMS setting fails here.
func probe(ctx context.Context, s recording.Storage) error {
	name := ".zanskar-probe-" + store.NewID()
	w, uri, err := s.Create(ctx, name)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	if _, err := io.WriteString(w, "zanskar probe\n"); err != nil {
		_ = w.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	rc, err := s.Open(ctx, uri)
	if err != nil {
		return fmt.Errorf("read back: %w", err)
	}
	b, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		return fmt.Errorf("read back: %w", err)
	}
	if string(b) != "zanskar probe\n" {
		return errors.New("read back: content differs")
	}
	if err := s.Delete(ctx, uri); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	return nil
}

// Test builds a backend from c and probes it, saving nothing.
func (m *Manager) Test(ctx context.Context, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	s, err := m.build(ctx, c)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := probe(ctx, s); err != nil {
		return fmt.Errorf("%w: probe failed: %w", ErrInvalid, err)
	}
	return nil
}

// Apply validates, probes, stores and activates c. When c keeps auth keys
// but sends no secret, the stored secret is kept.
func (m *Manager) Apply(ctx context.Context, c Config, by string) error {
	if c.Auth == AuthKeys && c.SecretAccessKey == "" {
		if cur, err := m.Repo.Get(ctx); err == nil && cur != nil && cur.AccessKeyID == strings.TrimSpace(c.AccessKeyID) {
			c.SecretAccessKey = cur.SecretAccessKey
		}
	}
	if err := c.Validate(); err != nil {
		return err
	}
	s, err := m.build(ctx, c)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := probe(ctx, s); err != nil {
		return fmt.Errorf("%w: probe failed: %w", ErrInvalid, err)
	}
	if err := m.Repo.Put(ctx, c, by); err != nil {
		return err
	}
	m.set(SourceConsole, &c, s)
	return nil
}

// Reset removes the console configuration; the environment's or the local
// directory serves again.
func (m *Manager) Reset(ctx context.Context) error {
	if err := m.Repo.Delete(ctx); err != nil {
		return err
	}
	return m.Load(ctx)
}

// MoveState reports the move in progress or last finished.
func (m *Manager) MoveState() Move {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.move
}

// StartMove copies every finished local recording to the active bucket in
// the background, verifying each copy's digest against the recording's
// before switching the row and deleting the local file. One move at a
// time; done reports the final state.
func (m *Manager) StartMove(ctx context.Context, done func(Move)) error {
	s := m.Router.S3()
	if s == nil {
		return fmt.Errorf("%w: no bucket is active", ErrInvalid)
	}
	m.mu.Lock()
	if m.move.Running {
		m.mu.Unlock()
		return ErrBusy
	}
	now := time.Now().UTC()
	m.move = Move{Running: true, StartedAt: &now}
	m.mu.Unlock()
	go func() {
		final := m.run(ctx, s)
		if done != nil {
			done(final)
		}
	}()
	return nil
}

func (m *Manager) run(ctx context.Context, s *recording.S3Storage) Move {
	var moved, failed, total int
	lastErr := ""
	after := ""
	for {
		batch, err := m.Sessions.ListRecordingsByURIPrefix(ctx, "file://", after, 100)
		if err != nil {
			lastErr = err.Error()
			break
		}
		if len(batch) == 0 {
			break
		}
		for _, rec := range batch {
			after = rec.ID
			total++
			if err := m.moveOne(ctx, s, rec); err != nil {
				failed++
				lastErr = err.Error()
				m.Log.Warn("move recording", "recording", rec.ID, "err", err)
				continue
			}
			moved++
			m.mu.Lock()
			m.move.Moved, m.move.Failed, m.move.Total = moved, failed, total
			m.mu.Unlock()
		}
	}
	end := time.Now().UTC()
	m.mu.Lock()
	m.move.Running, m.move.FinishedAt, m.move.Moved, m.move.Failed, m.move.Total, m.move.LastError = false, &end, moved, failed, total, lastErr
	final := m.move
	m.mu.Unlock()
	return final
}

func (m *Manager) moveOne(ctx context.Context, s *recording.S3Storage, rec *session.Recording) error {
	src, err := m.Router.Open(ctx, rec.StorageURI)
	if err != nil {
		return err
	}
	name := rec.ID + ".cast"
	if rec.Format == "guac" {
		name = rec.ID + ".guac"
	}
	dst, uri, err := s.Create(ctx, name)
	if err != nil {
		_ = src.Close()
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(dst, h), src); err != nil {
		_ = src.Close()
		_ = dst.Close()
		return err
	}
	_ = src.Close()
	if err := dst.Close(); err != nil {
		return err
	}
	if sum := hex.EncodeToString(h.Sum(nil)); rec.SHA256 != "" && sum != rec.SHA256 {
		_ = s.Delete(ctx, uri)
		return fmt.Errorf("digest of the copy (%s) differs from the recording's", sum[:12])
	}
	if err := m.Sessions.UpdateRecordingURI(ctx, rec.ID, rec.StorageURI, uri); err != nil {
		_ = s.Delete(ctx, uri)
		return err
	}
	if err := m.Router.Delete(ctx, rec.StorageURI); err != nil {
		m.Log.Warn("local recording not removed after move", "recording", rec.ID, "err", err)
	}
	return nil
}
