// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"

	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/store"
)

// stepVersion is the data step of ADR 0036, between 0035 (the subjects table
// and the grants column) and 0037 (the legacy columns dropped).
const stepVersion = "0036_policy_grants_data"

func init() {
	store.RegisterStep(store.Step{Version: stepVersion, Run: convertStored})
}

// legacyInventory is what the conversion needs to know about the ids a
// legacy selector names, which carry no kind: the live targets with their
// kind, and the live autoscaling groups.
type legacyInventory struct {
	targetKind map[string]string
	asgs       map[string]bool
}

// convert turns one legacy policy into subjects and grants with the same
// effective access: for every target and every protocol it can serve, the
// grants admit exactly what the policy admitted, under the same
// conditions. Named ids become rows of a grant of their kind, with the
// selector's protocols that kind serves; a tag selector becomes a tag rule
// on a grant for every kind its protocols reach, since it matched every kind
// before. Selectors naming the same targets or the same tags merge. dropped
// names the ids that granted nothing a connect could use: gone, retired, or
// of a kind that serves none of the selector's protocols.
func convert(p *legacyPolicy, inv legacyInventory, newID func() string) (subjects []Subject, grants []Grant, dropped []string) {
	if p.GroupID != "" {
		subjects = append(subjects, Subject{Kind: SubjectGroup, ID: p.GroupID})
	}
	if p.UserID != "" {
		subjects = append(subjects, Subject{Kind: SubjectUser, ID: p.UserID})
	}
	type pair struct {
		sel    legacySelector
		protos []string
	}
	var pairs []pair
	if !p.Selector.empty() && len(p.Protocols) > 0 {
		pairs = append(pairs, pair{p.Selector, p.Protocols})
	}
	for _, r := range p.Rules {
		pairs = append(pairs, pair{r.Selector, r.Protocols})
	}

	named := map[string]map[string][]string{} // kind -> id -> protocols
	order := map[string][]string{}            // kind -> ids, first seen first
	addNamed := func(kind, id string, protos []string) {
		if named[kind] == nil {
			named[kind] = map[string][]string{}
		}
		if _, ok := named[kind][id]; !ok {
			order[kind] = append(order[kind], id)
		}
		named[kind][id] = union(kind, named[kind][id], protos)
	}
	type tagged struct {
		kind   string
		match  map[string][]string
		protos []string
	}
	tags := map[string]*tagged{}
	var tagOrder []string
	drop := func(id, why string) {
		dropped = append(dropped, id+" ("+why+")")
	}
	for _, pr := range pairs {
		for _, id := range pr.sel.Targets {
			kind, ok := inv.targetKind[id]
			if !ok {
				drop(id, "no such live target")
				continue
			}
			if protos := servable(kind, pr.protos); len(protos) > 0 {
				addNamed(kind, id, protos)
			} else {
				drop(id, "a "+kind+" serves none of "+strings.Join(pr.protos, ", "))
			}
		}
		for _, id := range pr.sel.ASGs {
			if !inv.asgs[id] {
				drop(id, "no such live autoscaling group")
				continue
			}
			if protos := servable(protocol.KindAutoscaling, pr.protos); len(protos) > 0 {
				addNamed(protocol.KindAutoscaling, id, protos)
			} else {
				drop(id, "an autoscaling group serves none of "+strings.Join(pr.protos, ", "))
			}
		}
		if len(pr.sel.Tags) == 0 {
			continue
		}
		match := map[string][]string{}
		for k, v := range pr.sel.Tags {
			match[k] = []string{v}
		}
		for _, kind := range protocol.Kinds {
			protos := servable(kind, pr.protos)
			if len(protos) == 0 {
				continue
			}
			key := kind + "\x00" + canonical(pr.sel.Tags)
			if t, ok := tags[key]; ok {
				t.protos = union(kind, t.protos, protos)
				continue
			}
			tags[key] = &tagged{kind: kind, match: match, protos: protos}
			tagOrder = append(tagOrder, key)
		}
	}

	conditions := func(kind string) Grant {
		g := Grant{
			ID: newID(), Kind: kind, Targets: []GrantTarget{}, Access: AccessStanding, SignIn: SignInTarget,
			RequireMFA: p.RequireMFA, AllowClipboard: p.AllowClipboard, AllowFileTransfer: p.AllowFileTransfer,
			IdleTimeoutMinutes: p.IdleTimeoutMinutes, TimeWindows: slices.Clone(p.TimeWindows),
		}
		if p.RequireApproval {
			g.Access = AccessApproval
		}
		if p.MaxSessionMinutes != nil {
			v := *p.MaxSessionMinutes
			g.MaxSessionMinutes = &v
		}
		if p.RetentionDays != nil {
			v := *p.RetentionDays
			g.RetentionDays = &v
		}
		if g.TimeWindows == nil {
			g.TimeWindows = []TimeWindow{}
		}
		return g
	}
	for _, kind := range protocol.Kinds {
		if len(order[kind]) == 0 {
			continue
		}
		g := conditions(kind)
		for _, id := range order[kind] {
			g.Targets = append(g.Targets, GrantTarget{ID: id, Protocols: named[kind][id]})
		}
		grants = append(grants, g)
	}
	for _, key := range tagOrder {
		t := tags[key]
		g := conditions(t.kind)
		g.Tags = &TagMatch{Match: t.match, Protocols: t.protos}
		grants = append(grants, g)
	}
	return subjects, grants, dropped
}

// servable is the protocols of protos a thing of kind can serve, in the
// kind's own order.
func servable(kind string, protos []string) []string {
	var out []string
	for _, p := range protocol.KindProtocols(kind) {
		if slices.Contains(protos, p) {
			out = append(out, p)
		}
	}
	return out
}

// union merges two protocol lists of one kind, in the kind's order.
func union(kind string, a, b []string) []string {
	return servable(kind, append(slices.Clone(a), b...))
}

// canonical writes a tag map in key order, so equal selectors meet.
func canonical(tags map[string]string) string {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(tags[k])
		b.WriteByte(0)
	}
	return b.String()
}

// convertStored is the data step: every stored policy not yet converted
// (grants IS NULL) gets the grants convert makes from its legacy columns.
// 0035 has copied its subject into access_policy_subjects already. SQLite
// runs on one connection, so every read is drained and closed before the
// first write.
func convertStored(ctx context.Context, db *store.DB, tx *sql.Tx) error {
	inv, err := readInventory(ctx, tx)
	if err != nil {
		return err
	}
	legacy, err := readLegacy(ctx, tx)
	if err != nil {
		return err
	}
	for _, p := range legacy {
		_, grants, dropped := convert(p, inv, store.NewID)
		if grants == nil {
			grants = []Grant{}
		}
		body, err := json.Marshal(grants)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, db.Rebind(`UPDATE access_policies SET grants = ? WHERE id = ?`), body, p.ID); err != nil {
			return fmt.Errorf("policy %s: %w", p.Name, err)
		}
		// Not an error: these ids granted nothing a connect could use.
		if len(dropped) > 0 {
			slog.Info("policy conversion left out ids that granted nothing", "policy", p.Name, "ids", dropped)
		}
		if len(grants) == 0 {
			slog.Info("policy converted with no grant; it granted nothing before", "policy", p.Name)
		}
	}
	return nil
}

// readInventory reads the live targets with their kind and the live
// autoscaling groups.
func readInventory(ctx context.Context, tx *sql.Tx) (legacyInventory, error) {
	inv := legacyInventory{targetKind: map[string]string{}, asgs: map[string]bool{}}
	if err := eachRow(ctx, tx, `SELECT id, COALESCE(engine, ''), COALESCE(app_upstream, '') FROM targets WHERE deleted_at IS NULL`, func(rows *sql.Rows) error {
		var id, engine, upstream string
		if err := rows.Scan(&id, &engine, &upstream); err != nil {
			return err
		}
		switch {
		case engine != "":
			inv.targetKind[id] = protocol.KindDatabase
		case upstream != "":
			inv.targetKind[id] = protocol.KindApplication
		default:
			inv.targetKind[id] = protocol.KindHost
		}
		return nil
	}); err != nil {
		return inv, fmt.Errorf("read targets: %w", err)
	}
	if err := eachRow(ctx, tx, `SELECT id FROM autoscaling_groups WHERE deleted_at IS NULL`, func(rows *sql.Rows) error {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		inv.asgs[id] = true
		return nil
	}); err != nil {
		return inv, fmt.Errorf("read autoscaling groups: %w", err)
	}
	return inv, nil
}

// readLegacy reads the policies not yet converted, in name order.
func readLegacy(ctx context.Context, tx *sql.Tx) ([]*legacyPolicy, error) {
	var legacy []*legacyPolicy
	err := eachRow(ctx, tx, `SELECT id, name, enabled, group_id, user_id, target_selector, protocols, rules, time_windows,
		max_session_minutes, idle_timeout_minutes, retention_days, allow_clipboard, allow_file_transfer, require_mfa, require_approval
		FROM access_policies WHERE grants IS NULL ORDER BY name`, func(rows *sql.Rows) error {
		p, err := scanLegacy(rows)
		if err != nil {
			return err
		}
		legacy = append(legacy, p)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read policies: %w", err)
	}
	return legacy, nil
}

// eachRow runs q and calls fn for every row; the cursor is closed before it
// returns.
func eachRow(ctx context.Context, tx *sql.Tx, q string, fn func(*sql.Rows) error) error {
	rows, err := tx.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func scanLegacy(s store.Scanner) (*legacyPolicy, error) {
	var (
		p                        legacyPolicy
		sel, protos, rules, wins []byte
		groupID, userID          sql.NullString
		maxSession, retention    sql.NullInt64
	)
	if err := s.Scan(&p.ID, &p.Name, &p.Enabled, &groupID, &userID, &sel, &protos, &rules, &wins,
		&maxSession, &p.IdleTimeoutMinutes, &retention, &p.AllowClipboard, &p.AllowFileTransfer, &p.RequireMFA, &p.RequireApproval); err != nil {
		return nil, err
	}
	p.GroupID, p.UserID = groupID.String, userID.String
	for _, part := range []struct {
		raw  []byte
		into any
		what string
	}{{sel, &p.Selector, "selector"}, {protos, &p.Protocols, "protocols"}, {rules, &p.Rules, "rules"}, {wins, &p.TimeWindows, "time windows"}} {
		if len(part.raw) == 0 {
			continue
		}
		if err := json.Unmarshal(part.raw, part.into); err != nil {
			return nil, fmt.Errorf("policy %s: bad %s: %w", p.Name, part.what, err)
		}
	}
	if maxSession.Valid {
		v := int(maxSession.Int64)
		p.MaxSessionMinutes = &v
	}
	if retention.Valid {
		v := int(retention.Int64)
		p.RetentionDays = &v
	}
	return &p, nil
}
