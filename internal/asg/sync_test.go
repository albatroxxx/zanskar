// SPDX-License-Identifier: Apache-2.0

package asg

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/cloud"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/target"
)

// sshHost is a minimal SSH server that only completes the key exchange so a
// probe can capture its host key.
func sshHost(t *testing.T) (port int, fingerprint string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{NoClientAuth: false, PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, errors.New("no") }}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, _, _, err := ssh.NewServerConn(c, cfg)
				if err == nil {
					_ = sc.Close()
				}
				_ = c.Close()
			}()
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ = strconv.Atoi(p)
	return port, ssh.FingerprintSHA256(signer.PublicKey())
}

func newSyncer(t *testing.T) (*Syncer, *Repo, *cloud.Fake, *gateway.Registry) {
	t.Helper()
	d := testDB(t)
	repo := NewRepo(d)
	fake := cloud.NewFake()
	reg := gateway.NewRegistry()
	s := &Syncer{
		Repo:         repo,
		Providers:    func(context.Context, *Group) (cloud.Provider, error) { return fake, nil },
		Prober:       &target.Prober{AllowLoopback: true},
		Registry:     reg,
		Audit:        audit.NewLog(d),
		ProbeTimeout: 2 * time.Second,
	}
	return s, repo, fake, reg
}

func TestSyncPinsFromConsoleAndRetiresOnLoss(t *testing.T) {
	ctx := context.Background()
	s, repo, fake, reg := newSyncer(t)
	port, fp := sshHost(t)
	g := sample()
	g.Ports = map[target.Protocol]int{target.SSH: port}
	if err := repo.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	fake.Set("web-asg",
		cloud.Instance{ID: "i-1", PrivateIP: "127.0.0.1", AvailabilityZone: "ap-south-1a", LifecycleState: "InService", LBHealth: "healthy"},
		cloud.Instance{ID: "i-2", PrivateIP: "127.0.0.1", AvailabilityZone: "ap-south-1b", LifecycleState: "Pending"},
	)
	fake.Console["i-1"] = []string{fp}

	sum, err := s.SyncGroup(ctx, g)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Seen != 2 || sum.Joined != 2 || sum.Healthy != 1 {
		t.Fatalf("summary: %+v", sum)
	}
	healthy, _ := repo.Instances(ctx, g.ID, true)
	if len(healthy) != 1 || healthy[0].InstanceID != "i-1" || healthy[0].HostKeyFingerprint != fp || healthy[0].HostKeySource != "console" {
		t.Fatalf("i-1: %+v", healthy)
	}

	// A live session on i-1; the instance then drains and leaves the group.
	live := reg.Add(ctx, gateway.Live{SessionID: "s1", UserID: "u1", TargetID: healthy[0].ID, Protocol: "ssh"})
	fake.Set("web-asg", cloud.Instance{ID: "i-2", PrivateIP: "127.0.0.1", AvailabilityZone: "ap-south-1b", LifecycleState: "InService"})
	sum, err = s.SyncGroup(ctx, g)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Left != 1 {
		t.Fatalf("expected i-1 to leave: %+v", sum)
	}
	select {
	case <-live.Done():
		if reason, _ := gateway.CancelReason(live); reason != "target_lost" {
			t.Fatalf("cancel reason %q", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("live session on the lost instance was not ended")
	}
	// i-2 came up with no console keys: trust on first use, marked as such.
	all, _ := repo.Instances(ctx, g.ID, false)
	for _, in := range all {
		if in.InstanceID == "i-2" && (in.HostKeySource != "tofu" || in.HostKeyFingerprint != fp || !in.Healthy) {
			t.Fatalf("i-2 tofu pin: %+v", in)
		}
		if in.InstanceID == "i-1" && in.TerminatedAt == nil {
			t.Fatal("i-1 should be terminated")
		}
	}
	// Audit trail names the events.
	events, _, _ := s.Audit.List(ctx, audit.Filter{ObjectType: "asg_instance"})
	actions := map[string]int{}
	for _, e := range events {
		actions[e.Action]++
	}
	if actions["asg.instance.joined"] != 2 || actions["asg.instance.left"] != 1 {
		t.Fatalf("audit actions: %v", actions)
	}
}

func TestSyncRefusesToPinOnConsoleMismatch(t *testing.T) {
	ctx := context.Background()
	s, repo, fake, _ := newSyncer(t)
	port, _ := sshHost(t)
	g := sample()
	g.Ports = map[target.Protocol]int{target.SSH: port}
	if err := repo.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	fake.Set("web-asg", cloud.Instance{ID: "i-9", PrivateIP: "127.0.0.1", LifecycleState: "InService"})
	fake.Console["i-9"] = []string{"SHA256:SomethingElseEntirely0000000000000000000000"}
	sum, err := s.SyncGroup(ctx, g)
	if err != nil {
		t.Fatal(err)
	}
	if sum.HostKeyMismatches != 1 || sum.Healthy != 0 {
		t.Fatalf("summary: %+v", sum)
	}
	all, _ := repo.Instances(ctx, g.ID, false)
	if len(all) != 1 || all[0].HostKeyFingerprint != "" || all[0].Healthy {
		t.Fatalf("mismatched instance must not be pinned or healthy: %+v", all[0])
	}
}

func TestSyncRecordsProviderError(t *testing.T) {
	ctx := context.Background()
	s, repo, fake, _ := newSyncer(t)
	g := sample()
	if err := repo.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	fake.Err = cloud.ErrAccessDenied
	if _, err := s.SyncGroup(ctx, g); !errors.Is(err, cloud.ErrAccessDenied) {
		t.Fatalf("expected access denied, got %v", err)
	}
	got, _ := repo.Get(ctx, g.ID)
	if got.LastError == "" || got.LastSyncedAt == nil {
		t.Fatalf("error not recorded: %+v", got)
	}
}
