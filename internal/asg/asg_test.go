// SPDX-License-Identifier: Apache-2.0

package asg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/target"
)

func testDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func sample() *Group {
	return &Group{Name: "web", Region: "ap-south-1", ExternalName: "web-asg", RoleARN: "arn:aws:iam::123456789012:role/zanskar", OSFamily: target.Linux, Tags: map[string]string{"env": "prod"}}
}

func TestValidateAndDocuments(t *testing.T) {
	g := sample()
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(g.ExternalID, "zanskar-") || len(g.ExternalID) != len("zanskar-")+32 {
		t.Fatalf("external id not generated: %q", g.ExternalID)
	}
	if g.PollIntervalSeconds != 30 || g.AddressPreference != "private" || len(g.Capabilities) != 1 || g.Capabilities[0] != target.SSH {
		t.Fatalf("defaults: %+v", g)
	}
	if !strings.Contains(g.TrustPolicy(""), g.ExternalID) || !strings.Contains(g.TrustPolicy("arn:aws:iam::1:role/gw"), "arn:aws:iam::1:role/gw") {
		t.Fatal("trust policy must carry the ExternalId and principal")
	}
	if p := g.PermissionsPolicy(); !strings.Contains(p, "autoscaling:DescribeAutoScalingGroups") || !strings.Contains(p, "ec2-instance-connect:SendSSHPublicKey") || !strings.Contains(p, "web-asg") {
		t.Fatalf("permissions policy: %s", p)
	}
	bad := sample()
	bad.RoleARN = "not-an-arn"
	if err := bad.Validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("expected role arn validation")
	}
	bad = sample()
	bad.PollIntervalSeconds = 5
	if err := bad.Validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("expected poll interval validation")
	}
	if g.Port(target.SSH) != 22 {
		t.Fatal("default port")
	}
	g.AddressPreference = "public"
	if a := g.Address(&Instance{PrivateIP: "10.0.0.1", PublicIP: "3.3.3.3"}); a != "3.3.3.3" {
		t.Fatalf("address preference: %s", a)
	}
	if a := g.Address(&Instance{PrivateIP: "10.0.0.1"}); a != "10.0.0.1" {
		t.Fatalf("fallback address: %s", a)
	}
}

func TestRepoGroupsInstancesAndHealth(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	r := NewRepo(db)
	now := store.TimeArg(time.Now())
	if _, err := db.ExecContext(ctx, db.Rebind(`INSERT INTO credentials (id, name, type, mode, username, created_at, updated_at) VALUES ('c1', 'key', 'ssh_key', 'vaulted', 'ec2-user', ?, ?)`), now, now); err != nil {
		t.Fatal(err)
	}
	g := sample()
	g.Credentials = map[target.Protocol]string{target.SSH: "c1"}
	if err := r.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, sample()); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected duplicate, got %v", err)
	}
	got, err := r.Get(ctx, g.ID)
	if err != nil || got.Credentials[target.SSH] != "c1" || got.Tags["env"] != "prod" {
		t.Fatalf("get: %+v %v", got, err)
	}
	if err := r.SetCredential(ctx, g.ID, target.SSH, "missing"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected fk mapping, got %v", err)
	}

	launched := time.Now().Add(-time.Hour)
	in := &Instance{GroupID: g.ID, InstanceID: "i-1", PrivateIP: "10.0.0.5", LifecycleState: "InService", ProbeHealth: "healthy", HostKeyFingerprint: "SHA256:aaa", HostKeySource: "console", LaunchedAt: &launched}
	stored, isNew, err := r.UpsertInstance(ctx, in)
	if err != nil || !isNew || !stored.Healthy {
		t.Fatalf("first upsert: new=%v healthy=%v err=%v", isNew, stored.Healthy, err)
	}
	// Second sighting without a host key keeps the pinned one; LB draining makes it unhealthy.
	again, isNew, err := r.UpsertInstance(ctx, &Instance{GroupID: g.ID, InstanceID: "i-1", PrivateIP: "10.0.0.5", LifecycleState: "InService", LBHealth: "draining", ProbeHealth: "healthy"})
	if err != nil || isNew || again.ID != stored.ID || again.HostKeyFingerprint != "SHA256:aaa" || again.Healthy {
		t.Fatalf("second upsert: %+v new=%v err=%v", again, isNew, err)
	}
	if _, _, err := r.UpsertInstance(ctx, &Instance{GroupID: g.ID, InstanceID: "i-2", PrivateIP: "10.0.0.6", LifecycleState: "InService", ProbeHealth: "healthy"}); err != nil {
		t.Fatal(err)
	}
	healthy, err := r.Instances(ctx, g.ID, true)
	if err != nil || len(healthy) != 1 || healthy[0].InstanceID != "i-2" {
		t.Fatalf("healthy list: %v %v", healthy, err)
	}
	gone, err := r.MarkTerminated(ctx, g.ID, []string{"i-2"})
	if err != nil || len(gone) != 1 || gone[0].InstanceID != "i-1" {
		t.Fatalf("terminated: %v %v", gone, err)
	}
	all, _ := r.Instances(ctx, g.ID, false)
	if len(all) != 2 {
		t.Fatalf("expected 2 rows incl. terminated, got %d", len(all))
	}
	if err := r.RecordSync(ctx, g.ID, errors.New("boom")); err != nil {
		t.Fatal(err)
	}
	got, _ = r.Get(ctx, g.ID)
	if got.LastError != "boom" || got.LastSyncedAt == nil {
		t.Fatalf("sync record: %+v", got)
	}
	list, _ := r.List(ctx, true)
	if len(list) != 1 {
		t.Fatalf("list: %d", len(list))
	}
	if err := r.Delete(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, g.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("expected not found after delete")
	}
}
