// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"testing"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestAttentionListMatchesCountOnEachBackend (2026-10-30): the dashboard's
// "Hosts needing attention" opens the Hosts page narrowed to the same rows,
// each host once however many decisions it waits on; a disabled host and a
// database are in neither.
func TestAttentionListMatchesCountOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		for i, tg := range []*Target{
			{Name: "fine", Address: "10.0.0.1", OSFamily: Linux},
			{Name: "key-pending", Address: "10.0.0.2", OSFamily: Linux},
			{Name: "key-changed-and-cert", Address: "10.0.0.3", OSFamily: Windows},
			{Name: "winrm-cert", Address: "10.0.0.4", OSFamily: Windows},
			{Name: "disabled-pending", Address: "10.0.0.5", OSFamily: Linux, Status: StatusDisabled},
			{Name: "db", Address: "10.0.0.6", Engine: "postgres", TLSMode: "require", Ports: map[Protocol]int{"database": 5432}},
		} {
			if err := r.Create(ctx, tg); err != nil {
				t.Fatalf("%d: %v", i, err)
			}
		}
		for _, q := range []string{
			`UPDATE targets SET host_key_status = 'pending' WHERE name IN ('key-pending', 'disabled-pending')`,
			`UPDATE targets SET host_key_status = 'changed', tls_fingerprint_pending = 'aa' WHERE name = 'key-changed-and-cert'`,
			`UPDATE targets SET winrm_tls_fingerprint_pending = 'bb' WHERE name = 'winrm-cert'`,
			`UPDATE targets SET tls_fingerprint_pending = 'cc' WHERE name = 'db'`,
		} {
			if _, err := db.ExecContext(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
		c, err := r.CountAttention(ctx)
		if err != nil {
			t.Fatal(err)
		}
		list, _, err := r.List(ctx, "", 50, ListFilter{Kind: KindHost, Attention: true})
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, tg := range list {
			names = append(names, tg.Name)
		}
		if c.NeedingAttention != 3 || len(list) != c.NeedingAttention {
			t.Fatalf("counted %d, listed %v", c.NeedingAttention, names)
		}
		if c.HostKeyPending+c.HostKeyChanged+c.CertificatePending != 4 {
			t.Fatalf("per reason: %+v", c)
		}
	})
}
