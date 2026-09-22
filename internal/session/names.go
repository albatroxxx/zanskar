// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// nameSources maps an audit object type to the table and column that carry
// its display name. Only listed types are ever queried; the type comes from
// stored audit rows, never from the request.
var nameSources = map[string]struct{ table, col string }{
	"user":              {"users", "username"},
	"target":            {"targets", "name"},
	"group":             {"groups", "name"},
	"credential":        {"credentials", "name"},
	"access_policy":     {"access_policies", "name"},
	"autoscaling_group": {"autoscaling_groups", "name"},
	"identity_provider": {"identity_providers", "name"},
	"asg_instance":      {"asg_instances", "instance_id"},
}

// ResolveNames returns display names for audit object ids of one type, so a
// reviewer sees "aws-linux" and "admin" rather than hex ids. Sessions and
// recordings resolve to "user → target (protocol)". Unknown types and ids
// are simply absent from the result; the log itself is never touched.
func (r *Repo) ResolveNames(ctx context.Context, kind string, ids []string) (map[string]string, error) {
	uniq := dedupe(ids)
	if len(uniq) == 0 {
		return map[string]string{}, nil
	}
	switch kind {
	case "access_session", "session":
		return r.sessionLabels(ctx, "s.id", "", uniq)
	case "recording":
		return r.sessionLabels(ctx, "rec.id", "JOIN recordings rec ON rec.session_id = s.id", uniq)
	}
	src, ok := nameSources[kind]
	if !ok {
		return map[string]string{}, nil
	}
	q := fmt.Sprintf("SELECT id, %s FROM %s WHERE id IN (%s)", src.col, src.table, placeholders(len(uniq))) // #nosec G201 -- table and column come from the whitelist above
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(q), toArgs(uniq)...)
	if err != nil {
		return nil, fmt.Errorf("session: resolve %s names: %w", kind, err)
	}
	defer func() { _ = rows.Close() }()
	out := make(map[string]string, len(uniq))
	for rows.Next() {
		var id string
		var name sql.NullString
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		if name.Valid {
			out[id] = name.String
		}
	}
	return out, rows.Err()
}

// sessionLabels builds "user → target (protocol)" for sessions keyed by the
// given column; the optional join lets recordings resolve through their session.
func (r *Repo) sessionLabels(ctx context.Context, keyCol, join string, ids []string) (map[string]string, error) {
	q := `SELECT ` + keyCol + `, u.username, t.name, ai.instance_id, s.protocol FROM access_sessions s ` + join + `
		LEFT JOIN users u ON u.id = s.user_id
		LEFT JOIN targets t ON t.id = s.target_id
		LEFT JOIN asg_instances ai ON ai.id = s.asg_instance_id
		WHERE ` + keyCol + ` IN (` + placeholders(len(ids)) + `)`
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(q), toArgs(ids)...)
	if err != nil {
		return nil, fmt.Errorf("session: resolve session labels: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make(map[string]string, len(ids))
	for rows.Next() {
		var id, protocol string
		var username, target, instance sql.NullString
		if err := rows.Scan(&id, &username, &target, &instance, &protocol); err != nil {
			return nil, err
		}
		who := username.String
		if who == "" {
			who = "deleted user"
		}
		where := target.String
		if where == "" {
			where = instance.String
		}
		if where == "" {
			where = "unknown target"
		}
		out[id] = fmt.Sprintf("%s → %s (%s)", who, where, strings.ToUpper(protocol))
	}
	return out, rows.Err()
}

// UserIDByUsername looks a username up for audit filtering. It returns "" for
// an unknown name so the caller can filter to nothing rather than to everything.
func (r *Repo) UserIDByUsername(ctx context.Context, username string) (string, error) {
	var id string
	err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT id FROM users WHERE lower(username) = lower(?)`), username).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return id, err
}

func dedupe(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func toArgs(ids []string) []any {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return args
}
