// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// lastLegacy is the last migration of the policy shape before ADR 0036.
const lastLegacy = "0034_scim"

// TestMigrationConvertsStoredPolicies (ADR 0036): on each backend, a
// database at the last legacy schema, holding every legacy shape, migrates to
// the new one. Each policy keeps its one subject in the new table, gets the
// grants convert makes from its legacy columns, and grants what it granted;
// past sessions keep their policy; a second run converts nothing.
func TestMigrationConvertsStoredPolicies(t *testing.T) {
	storetest.ForEachBackendUpTo(t, lastLegacy, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		now := store.TimeArg(time.Now())
		exec := func(q string, args ...any) {
			t.Helper()
			if _, err := db.ExecContext(ctx, db.Rebind(q), args...); err != nil {
				t.Fatalf("%.60s: %v", q, err)
			}
		}
		exec(`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u', 'alice', 'Alice', ?, ?)`, now, now)
		exec(`INSERT INTO groups (id, name, created_at, updated_at) VALUES ('g', 'ops', ?, ?)`, now, now)
		exec(`INSERT INTO group_members (group_id, user_id, added_at) VALUES ('g', 'u', ?)`, now)
		for id, kind := range oracleInventory.targetKind {
			switch kind {
			case protocol.KindDatabase:
				exec(`INSERT INTO targets (id, name, address, os_family, engine, created_at, updated_at) VALUES (?, ?, '10.0.0.9', 'other', 'postgres', ?, ?)`, id, id, now, now)
			case protocol.KindApplication:
				exec(`INSERT INTO targets (id, name, address, os_family, app_upstream, created_at, updated_at) VALUES (?, ?, '', 'other', 'http://10.0.0.8', ?, ?)`, id, id, now, now)
			default:
				exec(`INSERT INTO targets (id, name, address, os_family, created_at, updated_at) VALUES (?, ?, '10.0.0.5', 'linux', ?, ?)`, id, id, now, now)
			}
		}
		// A retired target is no longer in the inventory.
		exec(`INSERT INTO targets (id, name, address, os_family, created_at, updated_at, deleted_at) VALUES ('gone', 'gone', '10.0.0.7', 'linux', ?, ?, ?)`, now, now, now)
		for id := range oracleInventory.asgs {
			exec(`INSERT INTO autoscaling_groups (id, name, provider, region, external_name, external_id, role_arn, os_family, created_at, updated_at) VALUES (?, ?, 'aws', 'ap-south-1', ?, 'ext', 'arn:aws:iam::123456789012:role/z', 'linux', ?, ?)`, id, id, id, now, now)
		}
		shapes := oracleShapes()
		for _, l := range shapes {
			sel, _ := json.Marshal(l.Selector)
			protos, _ := json.Marshal(nonNil(l.Protocols))
			rules, _ := json.Marshal(nonNilRules(l.Rules))
			wins, _ := json.Marshal(nonNilWindows(l.TimeWindows))
			exec(`INSERT INTO access_policies (id, name, description, enabled, group_id, user_id, target_selector, protocols, rules, time_windows,
				max_session_minutes, idle_timeout_minutes, retention_days, allow_clipboard, allow_file_transfer, require_mfa, require_approval, created_at, updated_at)
				VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				l.ID, l.Name, l.Enabled, nullStr(l.GroupID), nullStr(l.UserID), sel, protos, rules, wins,
				nullIntPtr(l.MaxSessionMinutes), l.IdleTimeoutMinutes, nullIntPtr(l.RetentionDays), l.AllowClipboard, l.AllowFileTransfer, l.RequireMFA, l.RequireApproval, now, now)
		}
		exec(`INSERT INTO access_sessions (id, user_id, policy_id, target_id, protocol, client_ip, started_at) VALUES ('s1', 'u', 'office-hours', 'h-prod', 'ssh', '10.0.0.1', ?)`, now)

		ran, err := store.Migrate(ctx, db)
		if err != nil {
			t.Fatalf("migrate: %v", err)
		}
		if len(ran) < 3 || ran[1] != stepVersion {
			t.Fatalf("ran %v, want the data step between 0035 and 0037", ran)
		}
		repo := NewRepo(db)
		var stored []*Policy
		for _, l := range shapes {
			p, err := repo.Get(ctx, l.ID)
			if err != nil {
				t.Fatalf("%s after the migration: %v", l.Name, err)
			}
			wantSubject := Subject{Kind: SubjectGroup, ID: "g"}
			if l.UserID != "" {
				wantSubject = Subject{Kind: SubjectUser, ID: "u"}
			}
			if len(p.Subjects) != 1 || p.Subjects[0] != wantSubject || p.Enabled != l.Enabled {
				t.Fatalf("%s: subjects %v enabled %v", l.Name, p.Subjects, p.Enabled)
			}
			stored = append(stored, p)
		}
		// What the database now holds grants what the legacy rows granted.
		for _, ref := range oracleTargets {
			for _, proto := range allProtocols {
				for _, at := range oracleInstants {
					compare(t, "migrated", shapes, stored, ref, proto, at)
				}
			}
		}
		// Alice reaches them through the new subjects table: directly and
		// through her group; the disabled one is left out.
		mine, err := repo.ForUser(ctx, "u")
		if err != nil || len(mine) != len(shapes)-1 {
			t.Fatalf("ForUser: %d policies %v, want every enabled one", len(mine), err)
		}
		var policyID string
		if err := db.QueryRowContext(ctx, `SELECT policy_id FROM access_sessions WHERE id = 's1'`).Scan(&policyID); err != nil || policyID != "office-hours" {
			t.Fatalf("a past session lost its policy across the rebuild: %q %v", policyID, err)
		}
		if again, err := store.Migrate(ctx, db); err != nil || len(again) != 0 {
			t.Fatalf("a second run: %v %v", again, err)
		}
	})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilRules(r []legacyRule) []legacyRule {
	if r == nil {
		return []legacyRule{}
	}
	return r
}

func nonNilWindows(w []TimeWindow) []TimeWindow {
	if w == nil {
		return []TimeWindow{}
	}
	return w
}

func nullIntPtr(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}
