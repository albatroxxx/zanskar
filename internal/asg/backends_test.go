// SPDX-License-Identifier: Apache-2.0

package asg

import (
	"context"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
	"github.com/albatroxxx/zanskar/internal/target"
)

// TestRepoOnEachBackend proves the autoscaling repository on both engines:
// the group's JSON columns, the per-instance upsert that pins the first host
// key, the health derivation and the termination sweep (review Q1,
// finding 2).
func TestRepoOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		now := store.TimeArg(time.Now())
		if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO credentials (id, name, type, mode, username, created_at, updated_at) VALUES ('c1', 'key', 'ssh_key', 'vaulted', 'ec2-user', ?, ?)`), now, now); err != nil {
			t.Fatal(err)
		}
		g := sample()
		g.Credentials = map[target.Protocol]string{target.SSH: "c1"}
		g.Ports = map[target.Protocol]int{target.SSH: 2222}
		if err := r.Create(ctx, g); err != nil {
			t.Fatal(err)
		}
		got, err := r.Get(ctx, g.ID)
		if err != nil || got.Credentials[target.SSH] != "c1" || got.Tags["env"] != "prod" || got.Ports[target.SSH] != 2222 {
			t.Fatalf("get: %+v %v", got, err)
		}
		launched := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
		first, isNew, err := r.UpsertInstance(ctx, &Instance{GroupID: g.ID, InstanceID: "i-1", PrivateIP: "10.0.0.5", LifecycleState: "InService", ProbeHealth: "healthy", HostKeyFingerprint: "SHA256:aaa", HostKeySource: "console", LaunchedAt: &launched})
		if err != nil || !isNew || !first.Healthy || first.LaunchedAt == nil || !first.LaunchedAt.Equal(launched) {
			t.Fatalf("first upsert: new=%v %+v %v", isNew, first, err)
		}
		// A sighting without a key keeps the pinned one; a draining load
		// balancer makes the instance unhealthy.
		second, isNew, err := r.UpsertInstance(ctx, &Instance{GroupID: g.ID, InstanceID: "i-1", PrivateIP: "10.0.0.5", LifecycleState: "InService", LBHealth: "draining", ProbeHealth: "healthy"})
		if err != nil || isNew || second.HostKeyFingerprint != "SHA256:aaa" || second.HostKeySource != "console" || second.Healthy {
			t.Fatalf("second sighting must keep the pinned key and read the LB health: new=%v %+v %v", isNew, second, err)
		}
		if _, _, err := r.UpsertInstance(ctx, &Instance{GroupID: g.ID, InstanceID: "i-2", PrivateIP: "10.0.0.6", LifecycleState: "InService", ProbeHealth: "healthy"}); err != nil {
			t.Fatal(err)
		}
		healthy, err := r.Instances(ctx, g.ID, true)
		if err != nil || len(healthy) != 1 || healthy[0].InstanceID != "i-2" {
			t.Fatalf("healthy instances: %+v %v", healthy, err)
		}
		gone, err := r.MarkTerminated(ctx, g.ID, []string{"i-2"})
		if err != nil || len(gone) != 1 || gone[0].InstanceID != "i-1" {
			t.Fatalf("terminated: %+v %v", gone, err)
		}
		// The terminated row stays, stamped, so history keeps its name
		// (ADR 0019); the healthy listing no longer has it.
		all, err := r.Instances(ctx, g.ID, false)
		if err != nil || len(all) != 2 {
			t.Fatalf("instances after the sweep: %d %v", len(all), err)
		}
		for _, in := range all {
			if (in.InstanceID == "i-1") != (in.TerminatedAt != nil) {
				t.Fatalf("termination stamp on %s: %v", in.InstanceID, in.TerminatedAt)
			}
		}
		if healthy, err = r.Instances(ctx, g.ID, true); err != nil || len(healthy) != 1 || healthy[0].InstanceID != "i-2" {
			t.Fatalf("healthy after the sweep: %+v %v", healthy, err)
		}
		if err := r.RecordSync(ctx, g.ID, nil); err != nil {
			t.Fatal(err)
		}
		if got, err = r.Get(ctx, g.ID); err != nil || got.LastSyncedAt == nil || got.LastError != "" {
			t.Fatalf("after a clean sync: %+v %v", got, err)
		}
	})
}
