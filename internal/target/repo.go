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
	engine, engine_version, retention_days, database_name, tls_mode, tls_ca, tls_fingerprint_pending, winrm_tls_fingerprint_pending,
	app_upstream`

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
		(id, name, address, os_family, ports, capabilities, host_key_status, tags, status, notes, created_by, created_at, updated_at, engine, engine_version, retention_days, database_name, tls_mode, tls_ca, app_upstream)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		t.ID, t.Name, t.Address, string(t.OSFamily), ports, capsJSON, string(HostKeyUnknown), tags, t.Status, t.Notes,
		nullStr(t.CreatedBy), store.TimeArg(now), store.TimeArg(now), t.Engine, t.EngineVersion, nullInt(t.RetentionDays), t.DatabaseName, t.TLSMode, t.TLSCA,
		emptyNull(t.AppUpstream))
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

// Retired targets (ADR 0019) are invisible to every lookup and listing; only
// the history queries in package session read past deleted_at.
func (r *Repo) getWhere(ctx context.Context, where string, arg any) (*Target, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+cols+` FROM targets WHERE deleted_at IS NULL AND `+where), arg)
	t, err := scanTarget(row)
	if err != nil {
		return nil, err
	}
	if t.Credentials, err = r.credentials(ctx, t.ID); err != nil {
		return nil, err
	}
	return t, nil
}

// ListFilter narrows List. Zero values match everything.
type ListFilter struct {
	Tags     map[string]string
	Kind     string // "host" | "database" | "application"
	Status   string // "active" | "disabled"
	OSFamily string
	Query    string // case-insensitive substring of name or address
	// Attention narrows to the targets that wait on an administrator's
	// decision, as CountAttention counts them.
	Attention bool
}

// attentionPredicate is what makes a target wait on an administrator: an SSH
// host key seen and not yet trusted, or changed after it was; or a
// certificate a probe saw after one was pinned (ADR 0012). CountAttention
// and List share it, so the dashboard's number and the list it opens count
// the same rows.
const attentionPredicate = `(host_key_status IN ('pending', 'changed') OR tls_fingerprint_pending IS NOT NULL OR winrm_tls_fingerprint_pending IS NOT NULL)`

// Kinds of target, as ListFilter.Kind and the admin API's kind= name them.
const (
	KindHost        = "host"
	KindDatabase    = "database"
	KindApplication = "application"
)

// kindClauses narrow a targets query to one kind. A host is what is neither
// a database nor an application.
var kindClauses = map[string]string{
	KindHost:        ` AND COALESCE(engine, '') = '' AND COALESCE(app_upstream, '') = ''`,
	KindDatabase:    ` AND COALESCE(engine, '') <> ''`,
	KindApplication: ` AND COALESCE(app_upstream, '') <> ''`,
}

// AttentionCounts are the target numbers the admin dashboard shows (ADR
// 0029): how many active targets exist, and how many wait on an
// administrator — a host key seen but not yet trusted, a host key that
// changed after trust (connections refused until resolved), or an RDP or
// WinRM certificate pin awaiting confirmation (ADR 0012).
type AttentionCounts struct {
	Active             int `json:"active"`
	HostKeyPending     int `json:"host_key_pending"`
	HostKeyChanged     int `json:"host_key_changed"`
	CertificatePending int `json:"certificate_pending"`
	// NeedingAttention counts each host once, however many of the above it
	// waits on: the number the dashboard shows and the Hosts page lists.
	NeedingAttention int `json:"needing_attention"`
}

// CountAttention returns AttentionCounts over active, undeleted hosts in one
// query: only a host's probe sees host keys and certificates, and the
// dashboard's tile opens the Hosts page.
func (r *Repo) CountAttention(ctx context.Context) (AttentionCounts, error) {
	var c AttentionCounts
	err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN host_key_status = ? THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN host_key_status = ? THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN tls_fingerprint_pending IS NOT NULL OR winrm_tls_fingerprint_pending IS NOT NULL THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN `+attentionPredicate+` THEN 1 ELSE 0 END), 0)
		FROM targets WHERE deleted_at IS NULL AND status = ?`+kindClauses[KindHost]),
		string(HostKeyPending), string(HostKeyChanged), StatusActive).
		Scan(&c.Active, &c.HostKeyPending, &c.HostKeyChanged, &c.CertificatePending, &c.NeedingAttention)
	return c, err
}

// Inventory is the fleet the admin dashboard shows (ADR 0029): how many
// hosts by OS family, how many databases by engine and how many applications
// (ADR 0033), active and undeleted.
type Inventory struct {
	Hosts        int            `json:"hosts"`
	HostsByOS    map[string]int `json:"hosts_by_os"`
	Databases    int            `json:"databases"`
	ByEngine     map[string]int `json:"databases_by_engine"`
	Applications int            `json:"applications"`
}

// CountInventory returns the Inventory in three counts, one after the other
// (single-connection SQLite).
func (r *Repo) CountInventory(ctx context.Context) (Inventory, error) {
	inv := Inventory{HostsByOS: map[string]int{}, ByEngine: map[string]int{}}
	count := func(column, kind string, into map[string]int) (int, error) {
		rows, err := r.db.QueryContext(ctx, `SELECT `+column+`, COUNT(*) FROM targets
			WHERE deleted_at IS NULL AND status = 'active'`+kindClauses[kind]+` GROUP BY `+column)
		if err != nil {
			return 0, err
		}
		defer func() { _ = rows.Close() }()
		total := 0
		for rows.Next() {
			var k string
			var n int
			if err := rows.Scan(&k, &n); err != nil {
				return 0, err
			}
			into[k] = n
			total += n
		}
		return total, rows.Err()
	}
	var err error
	if inv.Hosts, err = count("os_family", KindHost, inv.HostsByOS); err != nil {
		return Inventory{}, err
	}
	if inv.Databases, err = count("engine", KindDatabase, inv.ByEngine); err != nil {
		return Inventory{}, err
	}
	err = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM targets WHERE deleted_at IS NULL AND status = 'active'`+kindClauses[KindApplication]).Scan(&inv.Applications)
	if err != nil {
		return Inventory{}, err
	}
	return inv, nil
}

// List returns targets ordered by name after the cursor, narrowed by f.
func (r *Repo) List(ctx context.Context, afterName string, limit int, f ListFilter) ([]*Target, string, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := `SELECT ` + cols + ` FROM targets WHERE deleted_at IS NULL AND name > ?` + kindClauses[f.Kind]
	args := []any{afterName}
	if f.Status != "" {
		q += ` AND status = ?`
		args = append(args, f.Status)
	}
	if f.OSFamily != "" {
		q += ` AND os_family = ?`
		args = append(args, f.OSFamily)
	}
	if f.Attention {
		q += ` AND ` + attentionPredicate + ` AND status = '` + StatusActive + `'`
	}
	if s := strings.ToLower(strings.TrimSpace(f.Query)); s != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(s) + "%"
		q += ` AND (LOWER(name) LIKE ? ESCAPE '\' OR LOWER(address) LIKE ? ESCAPE '\')`
		args = append(args, like, like)
	}
	out, err := r.scanAll(ctx, r.db.Rebind(q+` ORDER BY name`), f.Tags, limit+1, args...)
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
	out, err := r.scanAll(ctx, `SELECT `+cols+` FROM targets WHERE deleted_at IS NULL AND status = 'active' ORDER BY name`, tags, 0)
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
	// A new address may be a different machine: what was trusted and pinned
	// for the old one says nothing about it. Clear the host key, its trust
	// and both certificate pins, so the next probe starts from "unknown"
	// rather than reporting a key change that looks like an attack.
	var oldAddress string
	if err := tx.QueryRowContext(ctx, r.db.Rebind(`SELECT address FROM targets WHERE id = ? AND deleted_at IS NULL`), t.ID).Scan(&oldAddress); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if oldAddress != t.Address {
		if _, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE targets SET host_key_fingerprint = NULL, host_key_status = 'unknown',
			tls_fingerprint = NULL, winrm_tls_fingerprint = NULL, tls_fingerprint_pending = NULL, winrm_tls_fingerprint_pending = NULL,
			last_probed_at = NULL WHERE id = ?`), t.ID); err != nil {
			return err
		}
		t.HostKeyFingerprint, t.HostKeyStatus, t.TLSFingerprint, t.WinRMTLSFingerprint, t.LastProbedAt = nil, HostKeyUnknown, nil, nil, nil
		t.TLSFingerprintPending, t.WinRMTLSFingerprintPending = nil, nil
	}
	res, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE targets SET name = ?, address = ?, os_family = ?, ports = ?, capabilities = ?,
		tags = ?, status = ?, notes = ?, engine = ?, engine_version = ?, retention_days = ?, database_name = ?, tls_mode = ?, tls_ca = ?,
		app_upstream = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`),
		t.Name, t.Address, string(t.OSFamily), mustJSON(t.Ports), mustJSON(t.Capabilities), mustJSON(t.Tags), t.Status, t.Notes,
		t.Engine, t.EngineVersion, nullInt(t.RetentionDays), t.DatabaseName, t.TLSMode, t.TLSCA,
		emptyNull(t.AppUpstream), store.TimeArg(now), t.ID)
	if err != nil {
		return mapErr(err)
	}
	if err := store.Affected(res, ErrNotFound); err != nil {
		return err
	}
	if err := replaceCredentialsTx(ctx, tx, r.db, t.ID, t.Credentials); err != nil {
		return err
	}
	t.UpdatedAt = now
	return tx.Commit()
}

// Delete retires the target (ADR 0019). The row stays so past sessions,
// recordings and audit events keep resolving to its name, but it leaves every
// listing and lookup, its credential bindings are dropped so the credentials
// themselves can later be deleted, and its name is free to enrol again.
// Whether anything still depends on it (policies naming it, open sessions) is
// the handler's decision; the repository only retires.
func (r *Repo) Delete(ctx context.Context, id string) error {
	now := store.TimeArg(time.Now().UTC())
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE targets SET deleted_at = ?, status = 'disabled', updated_at = ? WHERE id = ? AND deleted_at IS NULL`), now, now, id)
	if err != nil {
		return mapErr(err)
	}
	if err := store.Affected(res, ErrNotFound); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, r.db.Rebind(`DELETE FROM target_credentials WHERE target_id = ?`), id); err != nil {
		return err
	}
	return tx.Commit()
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
	// Certificates lists the pinned RDP or WinRM certificates the probe
	// found replaced; each was kept, with the new one held as pending.
	Certificates []CertificateChange `json:"certificates,omitempty"`
}

// CertificateChange is a pinned certificate a probe saw replaced.
type CertificateChange struct {
	Protocol Protocol `json:"protocol"` // rdp or winrm
	Pinned   string   `json:"pinned"`
	Seen     string   `json:"seen"`
}

// pinCertificate applies ADR 0012 to one listener: the first certificate a
// probe sees is pinned; the pinned one is never replaced by a probe. A
// different one is held as pending, and reported once, when it first
// appears; seeing the pinned one again clears a stale pending one.
func pinCertificate(pinned, pending **string, seen string, proto Protocol) *CertificateChange {
	switch {
	case *pinned == nil:
		*pinned, *pending = &seen, nil
	case **pinned == seen:
		*pending = nil
	case *pending == nil || **pending != seen:
		*pending = &seen
		return &CertificateChange{Protocol: proto, Pinned: **pinned, Seen: seen}
	}
	return nil
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
		if c := pinCertificate(&t.TLSFingerprint, &t.TLSFingerprintPending, res.TLS.Fingerprint, RDP); c != nil {
			change.Certificates = append(change.Certificates, *c)
		}
	}
	if res.WinRMTLS != nil && res.WinRMTLS.Fingerprint != "" {
		if c := pinCertificate(&t.WinRMTLSFingerprint, &t.WinRMTLSFingerprintPending, res.WinRMTLS.Fingerprint, WinRM); c != nil {
			change.Certificates = append(change.Certificates, *c)
		}
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
		tls_fingerprint = ?, winrm_tls_fingerprint = ?, tls_fingerprint_pending = ?, winrm_tls_fingerprint_pending = ?,
		last_probed_at = ?, updated_at = ? WHERE id = ?`),
		mustJSON(t.Capabilities), nullStr(t.HostKeyFingerprint), string(t.HostKeyStatus), nullStr(t.TLSFingerprint), nullStr(t.WinRMTLSFingerprint),
		nullStr(t.TLSFingerprintPending), nullStr(t.WinRMTLSFingerprintPending), store.TimeArg(now), store.TimeArg(now), id)
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
	if err := store.Affected(res, ErrNotFound); err != nil {
		return nil, ErrFingerprintMismatch
	}
	t.HostKeyStatus = HostKeyTrusted
	t.UpdatedAt = now
	return t, nil
}

// TrustCertificate is the administrator's confirmation of a pending RDP or
// WinRM certificate: it becomes the pinned one. The caller presents the
// fingerprint it is approving, so a probe racing the approval cannot get a
// different certificate pinned.
func (r *Repo) TrustCertificate(ctx context.Context, id string, proto Protocol, fingerprint string) (*Target, error) {
	t, err := r.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	pinCol, pendCol := "tls_fingerprint", "tls_fingerprint_pending"
	pinned, pending := &t.TLSFingerprint, &t.TLSFingerprintPending
	switch proto {
	case RDP:
	case WinRM:
		pinCol, pendCol = "winrm_tls_fingerprint", "winrm_tls_fingerprint_pending"
		pinned, pending = &t.WinRMTLSFingerprint, &t.WinRMTLSFingerprintPending
	default:
		return nil, fmt.Errorf("%w: protocol must be rdp or winrm", ErrInvalid)
	}
	if *pending == nil {
		return nil, ErrNoPendingCertificate
	}
	if fingerprint != **pending {
		return nil, ErrFingerprintMismatch
	}
	now := time.Now().UTC()
	// #nosec G202 -- column names come from the two constants above.
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE targets SET `+pinCol+` = ?, `+pendCol+` = NULL, updated_at = ? WHERE id = ? AND `+pendCol+` = ?`),
		fingerprint, store.TimeArg(now), id, fingerprint)
	if err != nil {
		return nil, err
	}
	if err := store.Affected(res, ErrNotFound); err != nil {
		return nil, ErrFingerprintMismatch
	}
	*pinned, *pending = &fingerprint, nil
	t.UpdatedAt = now
	return t, nil
}

// ---- internals

// scanAll runs a listing query, filters by tags in Go (tags are JSON in both
// databases) and stops after max rows when max > 0. The cursor is fully
// consumed and closed before it returns, which matters on SQLite where the
// pool holds a single connection: a follow-up query while rows are open
// would deadlock.
func (r *Repo) scanAll(ctx context.Context, q string, tags map[string]string, limit int, args ...any) ([]*Target, error) {
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
		if limit > 0 && len(out) >= limit {
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
	for _, p := range CredentialProtocols { // stable order keeps errors deterministic
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

func scanTarget(s store.Scanner) (*Target, error) {
	var (
		t                       Target
		osFamily, hkStatus      string
		ports, capsRaw, tagsRaw []byte
		hk, tlsFP, createdBy    sql.NullString
		winrmFP                 sql.NullString
		tlsPend, winrmPend      sql.NullString
		engine, engineVer       sql.NullString
		retention               sql.NullInt64
		dbName, tlsMode, tlsCA  sql.NullString
		appUpstream             sql.NullString
		created, updated, probe store.NullTime
	)
	err := s.Scan(&t.ID, &t.Name, &t.Address, &osFamily, &ports, &capsRaw, &hk, &hkStatus, &tlsFP, &tagsRaw,
		&t.Status, &t.Notes, &createdBy, &created, &updated, &probe, &winrmFP, &engine, &engineVer, &retention, &dbName, &tlsMode, &tlsCA, &tlsPend, &winrmPend,
		&appUpstream)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.OSFamily, t.HostKeyStatus = OSFamily(osFamily), HostKeyStatus(hkStatus)
	t.Engine, t.EngineVersion = engine.String, engineVer.String
	t.AppUpstream = appUpstream.String
	if retention.Valid {
		v := int(retention.Int64)
		t.RetentionDays = &v
	}
	t.DatabaseName, t.TLSMode, t.TLSCA = dbName.String, tlsMode.String, tlsCA.String
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
	if tlsPend.Valid {
		t.TLSFingerprintPending = &tlsPend.String
	}
	if winrmPend.Valid {
		t.WinRMTLSFingerprintPending = &winrmPend.String
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

// emptyNull stores "" as NULL: the application columns are absent on every
// other kind of target, and the label's unique index skips NULL.
func emptyNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func mapErr(err error) error {
	switch {
	case store.IsForeignKeyViolation(err):
		return ErrInvalidCredential
	case store.IsUniqueViolation(err):
		return ErrDuplicate
	}
	return err
}

func nullInt(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}
