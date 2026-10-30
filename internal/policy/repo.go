// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
)

// Repo reads and writes access policies.
type Repo struct {
	db *store.DB
}

// NewRepo returns a repository over db.
func NewRepo(db *store.DB) *Repo { return &Repo{db: db} }

const cols = `id, name, description, enabled, grants, created_by, created_at, updated_at`

// Create validates and inserts p with its subjects, setting the ids of the
// policy and of every grant, and the timestamps.
func (r *Repo) Create(ctx context.Context, p *Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	p.ID, p.CreatedAt, p.UpdatedAt = store.NewID(), now, now
	grants, err := encodeGrants(p)
	if err != nil {
		return err
	}
	return r.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, r.db.Rebind(`INSERT INTO access_policies (`+cols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
			p.ID, p.Name, p.Description, p.Enabled, grants, nullStr(p.CreatedBy), store.TimeArg(now), store.TimeArg(now)); err != nil {
			return mapErr(err)
		}
		return r.writeSubjects(ctx, tx, p)
	})
}

// Update replaces every editable field of the policy with the given id, its
// subjects included. A grant without an id is new and gets one.
func (r *Repo) Update(ctx context.Context, p *Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	grants, err := encodeGrants(p)
	if err != nil {
		return err
	}
	p.UpdatedAt = time.Now().UTC()
	return r.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE access_policies SET name = ?, description = ?, enabled = ?, grants = ?, updated_at = ? WHERE id = ?`),
			p.Name, p.Description, p.Enabled, grants, store.TimeArg(p.UpdatedAt), p.ID)
		if err != nil {
			return mapErr(err)
		}
		if err := store.Affected(res, ErrNotFound); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, r.db.Rebind(`DELETE FROM access_policy_subjects WHERE policy_id = ?`), p.ID); err != nil {
			return err
		}
		return r.writeSubjects(ctx, tx, p)
	})
}

func (r *Repo) writeSubjects(ctx context.Context, tx *sql.Tx, p *Policy) error {
	for _, s := range p.Subjects {
		var group, usr any
		if s.Kind == SubjectGroup {
			group = s.ID
		} else {
			usr = s.ID
		}
		if _, err := tx.ExecContext(ctx, r.db.Rebind(`INSERT INTO access_policy_subjects (policy_id, group_id, user_id) VALUES (?, ?, ?)`), p.ID, group, usr); err != nil {
			if store.IsForeignKeyViolation(err) {
				return fmt.Errorf("%w: %w: %s %s not found", ErrInvalidInput, ErrUnknownSubject, s.Kind, s.ID)
			}
			return err
		}
	}
	return nil
}

func (r *Repo) inTx(ctx context.Context, fn func(*sql.Tx) error) (err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Get returns one policy with its subjects.
func (r *Repo) Get(ctx context.Context, id string) (*Policy, error) {
	p, err := scan(r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+cols+` FROM access_policies WHERE id = ?`), id))
	if err != nil {
		return nil, err
	}
	if err := r.attachSubjects(ctx, []*Policy{p}); err != nil {
		return nil, err
	}
	return p, nil
}

// List returns policies ordered by name after the given name.
func (r *Repo) List(ctx context.Context, afterName string, limit int) ([]*Policy, string, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	out, err := r.query(ctx, `SELECT `+cols+` FROM access_policies WHERE name > ? ORDER BY name LIMIT ?`, afterName, limit+1)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].Name
	}
	if err := r.attachSubjects(ctx, out); err != nil {
		return nil, "", err
	}
	return out, next, nil
}

// query reads policies and drains the cursor before returning, so the
// caller may query again at once (SQLite runs on one connection).
func (r *Repo) query(ctx context.Context, q string, args ...any) ([]*Policy, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(q), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []*Policy{}
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// attachSubjects loads the subjects of ps in one statement, groups first,
// each kind in id order.
func (r *Repo) attachSubjects(ctx context.Context, ps []*Policy) error {
	if len(ps) == 0 {
		return nil
	}
	byID := make(map[string]*Policy, len(ps))
	args := make([]any, 0, len(ps))
	for _, p := range ps {
		p.Subjects = []Subject{}
		byID[p.ID] = p
		args = append(args, p.ID)
	}
	// The statement is built of "?" placeholders only; the ids are bound.
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT policy_id, group_id, user_id FROM access_policy_subjects
		WHERE policy_id IN (`+placeholders(len(args))+`) ORDER BY policy_id, user_id IS NOT NULL, group_id, user_id`), args...) // #nosec G701 -- placeholders only
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var pid string
		var group, usr sql.NullString
		if err := rows.Scan(&pid, &group, &usr); err != nil {
			return err
		}
		if p := byID[pid]; p != nil {
			if group.Valid {
				p.Subjects = append(p.Subjects, Subject{Kind: SubjectGroup, ID: group.String})
			} else {
				p.Subjects = append(p.Subjects, Subject{Kind: SubjectUser, ID: usr.String})
			}
		}
	}
	return rows.Err()
}

// Referencing returns, in name order, the names of policies with a grant
// that names the target or the autoscaling group by id. Tag rules are not
// references: they match whatever carries the tags, so retiring one target
// leaves them intact. Admin delete flows refuse while this is non-empty, so a
// machine a policy still names is never removed underneath it.
func (r *Repo) Referencing(ctx context.Context, targetID, asgID string) ([]string, error) {
	var names []string
	after := ""
	for {
		batch, next, err := r.List(ctx, after, 500)
		if err != nil {
			return nil, err
		}
		for _, p := range batch {
			if p.References(targetID, asgID) {
				names = append(names, p.Name)
			}
		}
		if next == "" {
			return names, nil
		}
		after = next
	}
}

// Removal is what deleting a target did, or would do, to one policy that
// named it (ADR 0036, amended 2026-10-30).
type Removal struct {
	PolicyID string `json:"policy_id"`
	Name     string `json:"name"`
	// GrantsRemoved counts the grants left naming nothing and matching no
	// tag, which go; NoGrantsLeft marks a policy left with none, which is
	// kept and grants nobody.
	GrantsRemoved int  `json:"grants_removed"`
	NoGrantsLeft  bool `json:"no_grants_left"`
}

// TargetUsage previews RemoveTargetTx without writing: the policies that
// name the target (or, for autoscaling grants, the group), in name order,
// and what deleting it would do to each.
func (r *Repo) TargetUsage(ctx context.Context, targetID, asgID string) ([]Removal, error) {
	out := []Removal{}
	after := ""
	for {
		batch, next, err := r.List(ctx, after, 500)
		if err != nil {
			return nil, err
		}
		for _, p := range batch {
			if grants, n, changed := p.WithoutTarget(targetID, asgID); changed {
				out = append(out, Removal{PolicyID: p.ID, Name: p.Name, GrantsRemoved: n, NoGrantsLeft: len(grants) == 0})
			}
		}
		if next == "" {
			return out, nil
		}
		after = next
	}
}

// RemoveTargetTx takes the target, or the autoscaling group, out of every
// grant that names it, inside the caller's transaction, so the target's own
// deletion and this commit or fail together. A grant left naming nothing
// and matching no tag goes; a policy left with no grant stays and grants
// nobody, as one left with no one does. Deleting a target used to be
// refused while any policy named it, so an administrator edited each one
// first (2026-10-30).
func (r *Repo) RemoveTargetTx(ctx context.Context, tx *sql.Tx, targetID, asgID string) ([]Removal, error) {
	// Every policy read, and the cursor closed, before the first write:
	// SQLite runs on one connection.
	rows, err := tx.QueryContext(ctx, r.db.Rebind(`SELECT `+cols+` FROM access_policies ORDER BY name`))
	if err != nil {
		return nil, err
	}
	var all []*Policy
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			_ = rows.Close() //nolint:sqlclosecheck // explicit close: SQLite single connection, writes follow
			return nil, err
		}
		all = append(all, p)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := []Removal{}
	now := store.TimeArg(time.Now().UTC())
	for _, p := range all {
		grants, n, changed := p.WithoutTarget(targetID, asgID)
		if !changed {
			continue
		}
		p.Grants = grants
		b, err := encodeGrants(p)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE access_policies SET grants = ?, updated_at = ? WHERE id = ?`), b, now, p.ID); err != nil {
			return nil, err
		}
		out = append(out, Removal{PolicyID: p.ID, Name: p.Name, GrantsRemoved: n, NoGrantsLeft: len(grants) == 0})
	}
	return out, nil
}

// Delete removes a policy and its subjects. Sessions and requests that
// name it keep a NULL policy_id.
func (r *Repo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM access_policies WHERE id = ?`), id)
	if err != nil {
		return err
	}
	return store.Affected(res, ErrNotFound)
}

// ForUser returns the enabled policies that apply to the user, directly or
// through a group they belong to, in name order. It is the input to
// Evaluate.
func (r *Repo) ForUser(ctx context.Context, userID string) ([]*Policy, error) {
	out, err := r.query(ctx, `SELECT `+qualify(cols, "p")+` FROM access_policies p
		WHERE p.enabled = TRUE AND EXISTS (SELECT 1 FROM access_policy_subjects s WHERE s.policy_id = p.id
			AND (s.user_id = ? OR s.group_id IN (SELECT group_id FROM group_members WHERE user_id = ?)))
		ORDER BY p.name`, userID, userID)
	if err != nil {
		return nil, err
	}
	return out, r.attachSubjects(ctx, out)
}

// ForGroup returns every policy that names the group, enabled or not, in
// name order: the policies a change to the group's membership, or its
// deletion, touches.
func (r *Repo) ForGroup(ctx context.Context, groupID string) ([]*Policy, error) {
	out, err := r.query(ctx, `SELECT `+qualify(cols, "p")+` FROM access_policies p
		WHERE EXISTS (SELECT 1 FROM access_policy_subjects s WHERE s.policy_id = p.id AND s.group_id = ?) ORDER BY p.name`, groupID)
	if err != nil {
		return nil, err
	}
	return out, r.attachSubjects(ctx, out)
}

// UsersCovered returns, sorted and once each, the users the subjects reach:
// the users named, and every member of the groups named. Revocation re-checks
// these users' sessions when a policy changes.
func (r *Repo) UsersCovered(ctx context.Context, subjects []Subject) ([]string, error) {
	seen := map[string]bool{}
	var groups []any
	for _, s := range subjects {
		if s.Kind == SubjectUser {
			seen[s.ID] = true
		} else {
			groups = append(groups, s.ID)
		}
	}
	if len(groups) > 0 {
		rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT DISTINCT user_id FROM group_members WHERE group_id IN (`+placeholders(len(groups))+`)`), groups...) // #nosec G701 -- placeholders only
		if err != nil {
			return nil, err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			seen[id] = true
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	slices.Sort(out)
	return out, nil
}

// ---- helpers

// encodeGrants gives every grant without an id one, and returns the grants
// as JSON.
func encodeGrants(p *Policy) ([]byte, error) {
	for i := range p.Grants {
		if p.Grants[i].ID == "" {
			p.Grants[i].ID = store.NewID()
		}
	}
	return json.Marshal(p.Grants)
}

func scan(s store.Scanner) (*Policy, error) {
	var (
		p                Policy
		grants           []byte
		createdBy        sql.NullString
		created, updated store.NullTime
	)
	if err := s.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &grants, &createdBy, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal(grants, &p.Grants); err != nil {
		return nil, fmt.Errorf("policy %s: bad grants: %w", p.ID, err)
	}
	if p.Grants == nil {
		p.Grants = []Grant{}
	}
	for i := range p.Grants {
		g := &p.Grants[i]
		if g.Targets == nil {
			g.Targets = []GrantTarget{}
		}
		if g.TimeWindows == nil {
			g.TimeWindows = []TimeWindow{}
		}
	}
	p.Subjects = []Subject{}
	p.CreatedBy = createdBy.String
	p.CreatedAt, p.UpdatedAt = created.Time, updated.Time
	return &p, nil
}

func qualify(columns, alias string) string {
	parts := strings.Split(columns, ",")
	for i, c := range parts {
		parts[i] = alias + "." + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func mapErr(err error) error {
	if store.IsUniqueViolation(err) {
		return ErrDuplicate
	}
	return err
}
