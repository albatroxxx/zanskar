// SPDX-License-Identifier: Apache-2.0

package asg

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
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

// winrmHost is a TLS listener standing in for a Windows instance's WinRM
// endpoint, so the sync loop has a certificate to pin. Each call generates a
// fresh certificate, so a restart looks like a re-imaged box.
func winrmHost(t *testing.T) (port int, fingerprint string, restart func() (int, string)) {
	t.Helper()
	start := func() (io.Closer, int, string) {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "winrm-lab"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12,
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					if tc, ok := c.(*tls.Conn); ok {
						_ = tc.HandshakeContext(context.Background())
					}
					_ = c.Close()
				}()
			}
		}()
		_, p, _ := net.SplitHostPort(ln.Addr().String())
		n, _ := strconv.Atoi(p)
		sum := sha256.Sum256(der)
		return ln, n, hex.EncodeToString(sum[:])
	}
	ln, port, fp := start()
	t.Cleanup(func() { _ = ln.Close() })
	return port, fp, func() (int, string) {
		_ = ln.Close()
		ln2, p2, fp2 := start()
		t.Cleanup(func() { _ = ln2.Close() })
		return p2, fp2
	}
}

// TestSyncPinsWindowsCertificatePerInstance is ADR 0024: an instance keeps the
// WinRM certificate it was first seen with, and a different one on the same
// instance makes it unhealthy instead of being trusted.
func TestSyncPinsWindowsCertificatePerInstance(t *testing.T) {
	ctx := context.Background()
	s, repo, fake, _ := newSyncer(t)
	port, fp, restart := winrmHost(t)
	g := sample()
	g.OSFamily, g.Capabilities = target.Windows, []target.Protocol{target.WinRM}
	g.Ports = map[target.Protocol]int{target.WinRM: port}
	if err := repo.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	fake.Set("web-asg", cloud.Instance{ID: "i-win", PrivateIP: "127.0.0.1", LifecycleState: "InService"})
	if _, err := s.SyncGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	all, _ := repo.Instances(ctx, g.ID, false)
	if len(all) != 1 || all[0].WinRMTLSFingerprint != fp || !all[0].Healthy {
		t.Fatalf("first sighting must pin and be healthy: %+v", all[0])
	}

	// Same instance, different certificate: refuse it.
	newPort, newFP := restart()
	if newFP == fp {
		t.Fatal("test setup: the replacement certificate must differ")
	}
	g.Ports = map[target.Protocol]int{target.WinRM: newPort}
	if err := repo.Update(ctx, g); err != nil {
		t.Fatal(err)
	}
	sum, err := s.SyncGroup(ctx, g)
	if err != nil {
		t.Fatal(err)
	}
	if sum.CertificateMismatches != 1 || sum.Healthy != 0 {
		t.Fatalf("summary: %+v", sum)
	}
	all, _ = repo.Instances(ctx, g.ID, false)
	if all[0].WinRMTLSFingerprint != fp || all[0].Healthy {
		t.Fatalf("pin must survive and the instance must be unhealthy: %+v", all[0])
	}
	events, _, _ := s.Audit.List(ctx, audit.Filter{ObjectType: "asg_instance"})
	found := false
	for _, e := range events {
		if e.Action == "asg.instance.certificate.changed" {
			found = true
		}
	}
	if !found {
		t.Fatal("a certificate change must be audited")
	}
}

// TestSyncStopsWhenTheStoredInstancesCannotBeRead: when the read of the
// group's stored instances fails, the poll must stop, not carry on as if
// every instance were new; that would re-pin a stored host key on first use
// (here: a different key on the same instance) with no changed event, and
// skip retiring sessions on instances that went unhealthy.
func TestSyncStopsWhenTheStoredInstancesCannotBeRead(t *testing.T) {
	ctx := context.Background()
	s, repo, fake, _ := newSyncer(t)
	port, fp := sshHost(t)
	otherPort, otherFP := sshHost(t)
	g := sample()
	g.Ports = map[target.Protocol]int{target.SSH: port}
	if err := repo.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	fake.Set("web-asg",
		cloud.Instance{ID: "i-1", PrivateIP: "127.0.0.1", AvailabilityZone: "ap-south-1a", LifecycleState: "InService", LBHealth: "healthy"},
		cloud.Instance{ID: "i-9", PrivateIP: "127.0.0.1", AvailabilityZone: "ap-south-1b", LifecycleState: "Pending"},
	)
	fake.Console["i-1"] = []string{fp}
	if _, err := s.SyncGroup(ctx, g); err != nil {
		t.Fatal(err)
	}

	// Next poll: i-1 answers with another key, and reading the group's
	// stored instances fails (another instance's row holds a value the
	// reader cannot decode, standing in for a transient read failure; i-1's
	// own row still reads and writes).
	g.Ports = map[target.Protocol]int{target.SSH: otherPort}
	delete(fake.Console, "i-1")
	fake.Set("web-asg", cloud.Instance{ID: "i-1", PrivateIP: "127.0.0.1", AvailabilityZone: "ap-south-1a", LifecycleState: "InService", LBHealth: "healthy"})
	if _, err := repo.db.ExecContext(ctx, `UPDATE asg_instances SET launched_at = 'not a time' WHERE instance_id = 'i-9'`); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Instances(ctx, g.ID, false); err == nil {
		t.Fatal("setup: the stored instances should not read")
	}
	_, _ = s.SyncGroup(ctx, g)
	var stored string
	if err := repo.db.QueryRowContext(ctx, `SELECT host_key_fingerprint FROM asg_instances WHERE instance_id = 'i-1'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != fp {
		t.Fatalf("pinned host key replaced on first use: stored %q, want %q (the new key was %q)", stored, fp, otherFP)
	}
}

// TestSyncAuditsAMismatchOncePerSighting: a host key or certificate mismatch
// was audited on every poll (B3), so one affected instance wrote about 2,880
// chained events a day at the 30 s default. A mismatch is now recorded when
// it is first seen; polls that see the same one again add nothing.
func TestSyncAuditsAMismatchOncePerSighting(t *testing.T) {
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
	for i := 0; i < 3; i++ {
		sum, err := s.SyncGroup(ctx, g)
		if err != nil {
			t.Fatal(err)
		}
		if sum.HostKeyMismatches != 1 {
			t.Fatalf("poll %d: the mismatch must still be counted: %+v", i+1, sum)
		}
	}
	events, _, err := s.Audit.List(ctx, audit.Filter{Action: audit.ASGInstanceHostKeyMismatch})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("three polls of one mismatch wrote %d audit events, want 1", len(events))
	}
}
