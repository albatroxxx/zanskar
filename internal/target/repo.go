// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
)

// Repo reads and writes targets.
type Repo struct {
	db *store.DB
}

// NewRepo returns a repository over db.
func NewRepo(db *store.DB) *Repo { return &Repo{db: db} }

const cols = `id, name, address, os_family, ports, capabilities, host_key_fingerprint, host_key_status,
	tls_fingerprint, tags, status, notes, created_by, created_at, updated_at, last_probed_at, winrm_tls_fingerprint,
	engine, engine_version`

// Create validates and inserts t, including its credential mapping.
func (r *Repo) Create(ctx context.Context, t *Target) error {
	if err := t.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	t.ID = store.NewID()
	t.CreatedAt, t.UpdatedAt = now, now
	t.HostKeyStatus = HostKeyUnknown
	t.HostKeyFingerprint, t.TLSFingerprint, t.WinRMTLSFingerprint, t.LastProbedAt = nil, nil, nil, nil
	ports, capsJSON, tags := mustJSON(t.Ports), mustJSON(t.Capabilities), mustJSON(t.Tags)

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	_, err = tx.ExecContext(ctx, r.db.Rebind(`INSERT INTO targets
		(id, name, address, os_family, ports, capabilities, host_key_status, tags, status, notes, created_by, created_at, updated_at, engine, engine_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		t.ID, t.Name, t.Address, string(t.OSFamily), ports, capsJSON, string(HostKeyUnknown), tags, t.Status, t.Notes,
		nullStr(t.CreatedBy), store.TimeArg(now), store.TimeArg(now), t.Engine, t.EngineVersion)
	if err != nil {
		return mapErr(err)
	}
	if err := replaceCredentialsTx(ctx, tx, r.db, t.ID, t.Credentials); err != nil {
		return err
	}
	return tx.Commit()
}

// Get returns a target by id.
func (r *Repo) Get(ctx context.Context, id string) (*Target, error) {
	return r.getWhere(ctx, "id = ?", id)
}

// GetByName returns a target by name.
func (r *Repo) GetByName(ctx context.Context, name string) (*Target, error) {
	return r.getWhere(ctx, "name = ?", name)
}

func (r *Repo) getWhere(ctx context.Context, where string, arg any) (*Target, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+cols+` FROM targets WHERE `+where), arg)
	t, err := scanTarget(row)
	if err != nil {
		return nil, err
	}
	if t.Credentials, err = r.credentials(ctx, t.ID); err != nil {
		return nil, err
	}
	return t, nil
}

// List returns targets ordered by name after the cursor. tags, when given,
// keeps only targets carrying every listed tag.
func (r *Repo) List(ctx context.Context, afterName string, limit int, tags map[string]string) ([]*Target, string, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	out, err := r.scanAll(ctx, r.db.Rebind(`SELECT `+cols+` FROM targets WHERE name > ? ORDER BY name`), tags, limit+1, afterName)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].Name
	}
	for _, t := range out {
		if t.Credentials, err = r.credentials(ctx, t.ID); err != nil {
			return nil, "", err
		}
	}
	if out == nil {
		out = []*Target{}
	}
	return out, next, nil
}

// ListByTags returns every active target carrying all of tags. Policies use it.
func (r *Repo) ListByTags(ctx context.Context, tags map[string]string) ([]*Target, error) {
	out, err := r.scanAll(ctx, `SELECT `+cols+` FROM targets WHERE status = 'active' ORDER BY name`, tags, 0)
	if err != nil {
		return nil, err
	}
	for _, t := range out {
		if t.Credentials, err = r.credentials(ctx, t.ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Update replaces the editable fields and the whole credential mapping.
// Probe-derived state (host key, TLS fingerprint, last probe) is untouched.
func (r *Repo) Update(ctx context.Context, t *Target) error {
	if err := t.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE targets SET name = ?, address = ?, os_family = ?, ports = ?, capabilities = ?,
		tags = ?, status = ?, notes = ?, engine = ?, engine_version = ?, updated_at = ? WHERE id = ?`),
		t.Name, t.Address, string(t.OSFamily), mustJSON(t.Ports), mustJSON(t.Capabilities), mustJSON(t.Tags), t.Status, t.Notes,
		t.Engine, t.EngineVersion, store.TimeArg(now), t.ID)
	if err != nil {
		return mapErr(err)
	}
	if err := affected(res); err != nil {
		return err
	}
	if err := replaceCredentialsTx(ctx, tx, r.db, t.ID, t.Credentials); err != nil {
		return err
	}
	t.UpdatedAt = now
	return tx.Commit()
}

// Delete removes the target and its credential mapping.
func (r *Repo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM targets WHERE id = ?`), id)
	if err != nil {
		return mapErr(err)
	}
	return affected(res)
}

// SetCredential maps a credential to one protocol.
func (r *Repo) SetCredential(ctx context.Context, targetID string, p Protocol, credentialID string) error {
	if !ValidProtocol(p) {
		return fmt.Errorf("%w: unknown protocol %q", ErrInvalid, p)
	}
	if credentialID == "" {
		return fmt.Errorf("%w: credential id required", ErrInvalid)
	}
	if _, err := r.Get(ctx, targetID); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, r.db.Rebind(`DELETE FROM target_credentials WHERE target_id = ? AND protocol = ?`), targetID, string(p)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, r.db.Rebind(`INSERT INTO target_credentials (target_id, protocol, credential_id) VALUES (?, ?, ?)`),
		targetID, string(p), credentialID); err != nil {
		return mapErr(err)
	}
	if _, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE targets SET updated_at = ? WHERE id = ?`), store.TimeArg(time.Now()), targetID); err != nil {
		return err
	}
	return tx.Commit()
}

// UnsetCredential removes the mapping for one protocol.
func (r *Repo) UnsetCredential(ctx context.Context, targetID string, p Protocol) error {
	if _, err := r.Get(ctx, targetID); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM target_credentials WHERE target_id = ? AND protocol = ?`), targetID, string(p))
	return err
}

// HostKeyChange describes what a probe did to host key trust.
type HostKeyChange struct {
	Old    *string       `json:"old"`
	New    *string       `json:"new"`
	Status HostKeyStatus `json:"status"`
	// Changed is true when a trusted key was replaced: the case that must be
	// audited and that blocks connections until an admin re-trusts.
	Changed bool `json:"changed"`
}

// RecordProbe stores a probe result and advances the host key state machine:
//
//	unknown + key      -> pending  (trust on first use, awaiting admin)
//	pending + same key -> pending
//	pending + new key  -> pending  (fingerprint replaced)
//	trusted + same key -> trusted
//	trusted + new key  -> changed  (never auto-accepted)
//	changed + any key  -> changed  (fingerprint tracks the newest seen)
//
// No SSH answer leaves the host key state untouched.
func (r *Repo) RecordProbe(ctx context.Context, id string, res ProbeResult) (*Target, *HostKeyChange, error) {
	t, err := r.Get(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	change := &HostKeyChange{Old: t.HostKeyFingerprint, Status: t.HostKeyStatus}
	if res.SSHHostKey != nil && res.SSHHostKey.Fingerprint != "" {
		fp := res.SSHHostKey.Fingerprint
		change.New = &fp
		switch t.HostKeyStatus {
		case HostKeyUnknown, HostKeyPending:
			change.Status = HostKeyPending
		case HostKeyTrusted:
			if t.HostKeyFingerprint != nil && *t.HostKeyFingerprint == fp {
				change.Status = HostKeyTrusted
			} else {
				change.Status = HostKeyChanged
				change.Changed = true
			}
		case HostKeyChanged:
			change.Status = HostKeyChanged
		}
		t.HostKeyFingerprint = &fp
		t.HostKeyStatus = change.Status
	} else {
		change.New = t.HostKeyFingerprint
	}
	if res.TLS != nil && res.TLS.Fingerprint != "" {
		fp := res.TLS.Fingerprint
		t.TLSFingerprint = &fp
	}
	if res.WinRMTLS != nil && res.WinRMTLS.Fingerprint != "" {
		fp := res.WinRMTLS.Fingerprint
		t.WinRMTLSFingerprint = &fp
	}
	caps := res.Capabilities
	if caps == nil {
		caps = []Protocol{}
	}
	t.Capabilities = caps
	now := res.ProbedAt
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	t.LastProbedAt = &now
	t.UpdatedAt = now
	_, err = r.db.ExecContext(ctx, r.db.Rebind(`UPDATE targets SET capabilities = ?, host_key_fingerprint = ?, host_key_status = ?,
		tls_fingerprint = ?, winrm_tls_fingerprint = ?, last_probed_at = ?, updated_at = ? WHERE id = ?`),
		mustJSON(t.Capabilities), nullStr(t.HostKeyFingerprint), string(t.HostKeyStatus), nullStr(t.TLSFingerprint), nullStr(t.WinRMTLSFingerprint),
		store.TimeArg(now), store.TimeArg(now), id)
	if err != nil {
		return nil, nil, err
	}
	return t, change, nil
}

// TrustHostKey is the admin approval step. The caller must present the
// fingerprint it is approving so a probe that races with the approval cannot
// get a different key trusted.
func (r *Repo) TrustHostKey(ctx context.Context, id, fingerprint string) (*Target, error) {
	t, err := r.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if t.HostKeyFingerprint == nil || (t.HostKeyStatus != HostKeyPending && t.HostKeyStatus != HostKeyChanged) {
		return nil, ErrNoPendingHostKey
	}
	if fingerprint != *t.HostKeyFingerprint {
		return nil, ErrFingerprintMismatch
	}
	now := time.Now().UTC()
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE targets SET host_key_status = ?, updated_at = ? WHERE id = ? AND host_key_fingerprint = ?`),
		string(HostKeyTrusted), store.TimeArg(now), id, fingerprint)
	if err != nil {
		return nil, err
	}
	if err := affected(res); err != nil {
		return nil, ErrFingerprintMismatch
	}
	t.HostKeyStatus = HostKeyTrusted
	t.UpdatedAt = now
	return t, nil
}

// ---- internals

// scanAll runs a listing query, filters by tags in Go (tags are JSON in both
// databases) and stops after max rows when max > 0. The cursor is fully
// consumed and closed before it returns, which matters on SQLite where the
// pool holds a single connection: a follow-up query while rows are open
// would deadlock.
func (r *Repo) scanAll(ctx context.Context, q string, tags map[string]string, max int, args ...any) ([]*Target, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Target{}
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		if !t.MatchesTags(tags) {
			continue
		}
		out = append(out, t)
		if max > 0 && len(out) >= max {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, rows.Close()
}

func (r *Repo) credentials(ctx context.Context, id string) (map[Protocol]string, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT protocol, credential_id FROM target_credentials WHERE target_id = ?`), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[Protocol]string{}
	for rows.Next() {
		var p, c string
		if err := rows.Scan(&p, &c); err != nil {
			return nil, err
		}
		out[Protocol(p)] = c
	}
	return out, rows.Err()
}

func replaceCredentialsTx(ctx context.Context, tx *sql.Tx, db *store.DB, id string, creds map[Protocol]string) error {
	if _, err := tx.ExecContext(ctx, db.Rebind(`DELETE FROM target_credentials WHERE target_id = ?`), id); err != nil {
		return err
	}
	for _, p := range Protocols { // stable order keeps errors deterministic
		c, ok := creds[p]
		if !ok {
			continue
		}
		if _, err := tx.ExecContext(ctx, db.Rebind(`INSERT INTO target_credentials (target_id, protocol, credential_id) VALUES (?, ?, ?)`),
			id, string(p), c); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

type scanner interface{ Scan(dest ...any) error }

func scanTarget(s scanner) (*Target, error) {
	var (
		t                       Target
		osFamily, hkStatus      string
		ports, capsRaw, tagsRaw []byte
		hk, tlsFP, createdBy    sql.NullString
		winrmFP                 sql.NullString
		engine, engineVer       sql.NullString
		created, updated, probe store.NullTime
	)
	err := s.Scan(&t.ID, &t.Name, &t.Address, &osFamily, &ports, &capsRaw, &hk, &hkStatus, &tlsFP, &tagsRaw,
		&t.Status, &t.Notes, &createdBy, &created, &updated, &probe, &winrmFP, &engine, &engineVer)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.OSFamily, t.HostKeyStatus = OSFamily(osFamily), HostKeyStatus(hkStatus)
	t.Engine, t.EngineVersion = engine.String, engineVer.String
	t.Ports, t.Capabilities, t.Tags = map[Protocol]int{}, []Protocol{}, map[string]string{}
	if len(ports) > 0 {
		_ = json.Unmarshal(ports, &t.Ports)
	}
	if len(capsRaw) > 0 {
		_ = json.Unmarshal(capsRaw, &t.Capabilities)
	}
	if len(tagsRaw) > 0 {
		_ = json.Unmarshal(tagsRaw, &t.Tags)
	}
	if hk.Valid {
		t.HostKeyFingerprint = &hk.String
	}
	if tlsFP.Valid {
		t.TLSFingerprint = &tlsFP.String
	}
	if winrmFP.Valid {
		t.WinRMTLSFingerprint = &winrmFP.String
	}
	if createdBy.Valid {
		t.CreatedBy = &createdBy.String
	}
	t.CreatedAt, t.UpdatedAt, t.LastProbedAt = created.Time, updated.Time, probe.Ptr()
	t.Credentials = map[Protocol]string{}
	return &t, nil
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic("target: marshal: " + err.Error())
	}
	return string(b)
}

func nullStr(s *string) any {
	if s == nil || *s == "" {
		return nil
	}
	return *s
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

func mapErr(err error) error {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "foreign key"):
		return ErrInvalidCredential
	case strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate key"):
		return ErrDuplicate
	}
	return err
}
