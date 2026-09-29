// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
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

func insertCredential(t *testing.T, db *store.DB, id string) {
	t.Helper()
	now := store.TimeArg(time.Now())
	_, err := db.ExecContext(context.Background(), db.Rebind(`INSERT INTO credentials (id, name, type, mode, created_at, updated_at) VALUES (?, ?, 'ssh_key', 'vaulted', ?, ?)`),
		id, "cred-"+id, now, now)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidate(t *testing.T) {
	good := &Target{Name: "web-1", Address: "10.0.0.5", OSFamily: Linux}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if good.Status != StatusActive || good.Ports == nil || good.Tags == nil || good.Credentials == nil {
		t.Fatal("defaults not applied")
	}
	bad := []Target{
		{Name: "", Address: "10.0.0.5", OSFamily: Linux},
		{Name: "x", Address: "http://10.0.0.5", OSFamily: Linux},
		{Name: "x", Address: "10.0.0.5:22", OSFamily: Linux},
		{Name: "x", Address: "host name", OSFamily: Linux},
		{Name: "x", Address: "10.0.0.5", OSFamily: "bsd"},
		{Name: "x", Address: "10.0.0.5", OSFamily: Linux, Ports: map[Protocol]int{SSH: 70000}},
		{Name: "x", Address: "10.0.0.5", OSFamily: Linux, Ports: map[Protocol]int{"telnet": 23}},
		{Name: "x", Address: "10.0.0.5", OSFamily: Linux, Tags: map[string]string{"": "v"}},
		{Name: "x", Address: "10.0.0.5", OSFamily: Linux, Status: "sleeping"},
		{Name: "x", Address: "10.0.0.5", OSFamily: Linux, Capabilities: []Protocol{"ftp"}},
	}
	for i, b := range bad {
		if err := b.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d: expected ErrInvalid, got %v", i, err)
		}
	}
	for _, a := range []string{"db.internal", "db-01.prod.example.com", "2001:db8::1", "192.0.2.10"} {
		if !ValidAddress(a) {
			t.Errorf("%q should be valid", a)
		}
	}
}

func TestRepoCRUD(t *testing.T) {
	db := testDB(t)
	r := NewRepo(db)
	ctx := context.Background()
	insertCredential(t, db, "c1")

	tg := &Target{Name: "web-1", Address: "10.0.0.5", OSFamily: Linux, Tags: map[string]string{"env": "prod", "team": "web"},
		Ports: map[Protocol]int{SSH: 2222}, Credentials: map[Protocol]string{SSH: "c1"}}
	if err := r.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, tg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Port(SSH) != 2222 || got.Port(RDP) != 3389 || got.Credentials[SSH] != "c1" || got.HostKeyStatus != HostKeyUnknown || got.Tags["env"] != "prod" {
		t.Fatalf("unexpected target: %+v", got)
	}
	if err := r.Create(ctx, &Target{Name: "web-1", Address: "10.0.0.6", OSFamily: Linux}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected duplicate, got %v", err)
	}
	if err := r.Create(ctx, &Target{Name: "bad-cred", Address: "10.0.0.7", OSFamily: Linux, Credentials: map[Protocol]string{SSH: "missing"}}); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("expected invalid credential, got %v", err)
	}

	for _, n := range []string{"web-2", "db-1"} {
		if err := r.Create(ctx, &Target{Name: n, Address: n + ".internal", OSFamily: Linux, Tags: map[string]string{"env": "prod"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Create(ctx, &Target{Name: "win-1", Address: "10.0.0.9", OSFamily: Windows, Tags: map[string]string{"env": "dev"}}); err != nil {
		t.Fatal(err)
	}
	page, next, err := r.List(ctx, "", 2, ListFilter{})
	if err != nil || len(page) != 2 || next != "web-1" {
		t.Fatalf("page1: n=%d next=%q err=%v", len(page), next, err)
	}
	page, next, err = r.List(ctx, next, 2, ListFilter{})
	if err != nil || len(page) != 2 || next != "" {
		t.Fatalf("page2: n=%d next=%q err=%v", len(page), next, err)
	}
	prod, _, err := r.List(ctx, "", 50, ListFilter{Tags: map[string]string{"env": "prod"}})
	if err != nil || len(prod) != 3 {
		t.Fatalf("tag filter: n=%d err=%v", len(prod), err)
	}
	byTags, err := r.ListByTags(ctx, map[string]string{"env": "prod", "team": "web"})
	if err != nil || len(byTags) != 1 || byTags[0].Name != "web-1" {
		t.Fatalf("ListByTags: %v %v", byTags, err)
	}

	got.Name, got.Notes, got.Status = "web-1a", "renamed", StatusDisabled
	got.Credentials = map[Protocol]string{}
	if err := r.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	got, _ = r.Get(ctx, tg.ID)
	if got.Name != "web-1a" || got.Status != StatusDisabled || len(got.Credentials) != 0 {
		t.Fatalf("update not applied: %+v", got)
	}
	if active, _ := r.ListByTags(ctx, map[string]string{"team": "web"}); len(active) != 0 {
		t.Fatal("disabled targets must not be listed by tags")
	}

	if err := r.SetCredential(ctx, tg.ID, RDP, "c1"); err != nil {
		t.Fatal(err)
	}
	if err := r.SetCredential(ctx, tg.ID, RDP, "nope"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("expected invalid credential, got %v", err)
	}
	if err := r.SetCredential(ctx, tg.ID, "ftp", "c1"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected invalid protocol, got %v", err)
	}
	got, _ = r.Get(ctx, tg.ID)
	if got.Credentials[RDP] != "c1" {
		t.Fatal("SetCredential not applied")
	}
	if err := r.UnsetCredential(ctx, tg.ID, RDP); err != nil {
		t.Fatal(err)
	}
	got, _ = r.Get(ctx, tg.ID)
	if _, ok := got.Credentials[RDP]; ok {
		t.Fatal("UnsetCredential not applied")
	}

	if err := r.Delete(ctx, tg.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, tg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("expected not found after delete")
	}
	if err := r.Delete(ctx, tg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("double delete must be not found")
	}
}

func TestHostKeyStateMachine(t *testing.T) {
	r := NewRepo(testDB(t))
	ctx := context.Background()
	tg := &Target{Name: "ssh-1", Address: "10.0.0.5", OSFamily: Linux}
	if err := r.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	probe := func(fingerprint string, reachable ...Protocol) ProbeResult {
		res := ProbeResult{Capabilities: reachable, ProbedAt: time.Now()}
		if fingerprint != "" {
			res.SSHHostKey = &SSHHostKey{Fingerprint: fingerprint, Type: "ssh-ed25519"}
		}
		return res
	}

	// No SSH answer: state untouched, capabilities recorded.
	got, ch, err := r.RecordProbe(ctx, tg.ID, probe("", RDP))
	if err != nil || got.HostKeyStatus != HostKeyUnknown || ch.Changed || len(got.Capabilities) != 1 || got.LastProbedAt == nil {
		t.Fatalf("no-ssh probe: %+v %+v %v", got, ch, err)
	}
	// First key: pending.
	got, ch, _ = r.RecordProbe(ctx, tg.ID, probe("SHA256:AAA", SSH))
	if got.HostKeyStatus != HostKeyPending || *got.HostKeyFingerprint != "SHA256:AAA" || ch.Status != HostKeyPending || ch.Changed {
		t.Fatalf("first key: %+v %+v", got, ch)
	}
	// Different key while pending: still pending, fingerprint replaced.
	got, _, _ = r.RecordProbe(ctx, tg.ID, probe("SHA256:BBB", SSH))
	if got.HostKeyStatus != HostKeyPending || *got.HostKeyFingerprint != "SHA256:BBB" {
		t.Fatalf("pending replace: %+v", got)
	}
	// Trust requires the exact pending fingerprint.
	if _, err := r.TrustHostKey(ctx, tg.ID, "SHA256:AAA"); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("expected mismatch, got %v", err)
	}
	got, err = r.TrustHostKey(ctx, tg.ID, "SHA256:BBB")
	if err != nil || got.HostKeyStatus != HostKeyTrusted {
		t.Fatalf("trust: %v %+v", err, got)
	}
	if _, err := r.TrustHostKey(ctx, tg.ID, "SHA256:BBB"); !errors.Is(err, ErrNoPendingHostKey) {
		t.Fatalf("re-trust of trusted key should report nothing pending, got %v", err)
	}
	// Same key while trusted: stays trusted.
	got, ch, _ = r.RecordProbe(ctx, tg.ID, probe("SHA256:BBB", SSH))
	if got.HostKeyStatus != HostKeyTrusted || ch.Changed {
		t.Fatalf("trusted same: %+v %+v", got, ch)
	}
	// New key while trusted: changed, never auto-accepted, old key reported.
	got, ch, _ = r.RecordProbe(ctx, tg.ID, probe("SHA256:EVIL", SSH))
	if got.HostKeyStatus != HostKeyChanged || !ch.Changed || *ch.Old != "SHA256:BBB" || *ch.New != "SHA256:EVIL" {
		t.Fatalf("changed: %+v %+v", got, ch)
	}
	// Stays changed on further probes; admin can re-trust after investigation.
	got, ch, _ = r.RecordProbe(ctx, tg.ID, probe("SHA256:EVIL", SSH))
	if got.HostKeyStatus != HostKeyChanged || ch.Changed {
		t.Fatalf("still changed, not a new change event: %+v %+v", got, ch)
	}
	if got, err := r.TrustHostKey(ctx, tg.ID, "SHA256:EVIL"); err != nil || got.HostKeyStatus != HostKeyTrusted {
		t.Fatalf("re-trust after change: %v", err)
	}
	if _, _, err := r.RecordProbe(ctx, "missing", probe("x")); !errors.Is(err, ErrNotFound) {
		t.Fatal("expected not found")
	}
}

func TestRecordProbeStoresWinRMFingerprint(t *testing.T) {
	r := NewRepo(testDB(t))
	ctx := context.Background()
	tg := &Target{Name: "win-1", Address: "10.0.0.9", OSFamily: Windows}
	if err := r.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	res := ProbeResult{
		Ports:        map[Protocol]PortResult{WinRM: {Reachable: true}, RDP: {Reachable: true}},
		Capabilities: []Protocol{RDP, WinRM},
		TLS:          &TLSInfo{Fingerprint: "aa11", Subject: "CN=rdp", Source: "rdp"},
		WinRMTLS:     &TLSInfo{Fingerprint: "bb22", Subject: "CN=winrm", Source: "winrm"},
	}
	if _, _, err := r.RecordProbe(ctx, tg.ID, res); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, tg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TLSFingerprint == nil || *got.TLSFingerprint != "aa11" || got.WinRMTLSFingerprint == nil || *got.WinRMTLSFingerprint != "bb22" {
		t.Fatalf("fingerprints not stored separately: rdp=%v winrm=%v", got.TLSFingerprint, got.WinRMTLSFingerprint)
	}
}

// TestDeleteRetiresTarget pins the retirement model of ADR 0019. Deleting a
// target that past sessions point at used to fail on the sessions table's
// CHECK constraint (target_id or asg_instance_id must be set), which the API
// surfaced as an internal error. Now the row stays for the history and
// vanishes from every lookup, its credential bindings go, and its name can
// be enrolled again.
func TestDeleteRetiresTarget(t *testing.T) {
	db := testDB(t)
	r := NewRepo(db)
	ctx := context.Background()
	insertCredential(t, db, "c1")
	tg := &Target{Name: "web-1", Address: "10.0.0.5", OSFamily: Linux, Tags: map[string]string{"env": "prod"}, Credentials: map[Protocol]string{SSH: "c1"}}
	if err := r.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	now := store.TimeArg(time.Now())
	for _, q := range []string{
		`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice', ?, ?)`,
		`INSERT INTO access_sessions (id, user_id, target_id, protocol, client_ip, started_at, ended_at, end_reason) VALUES ('s1', 'u1', '` + tg.ID + `', 'ssh', '10.0.0.1', ?, ?, 'user_exit')`,
	} {
		if _, err := db.ExecContext(ctx, db.Rebind(q), now, now); err != nil {
			t.Fatalf("%s: %v", q[:30], err)
		}
	}

	if err := r.Delete(ctx, tg.ID); err != nil {
		t.Fatalf("delete with session history: %v", err)
	}
	if _, err := r.Get(ctx, tg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after retire: %v", err)
	}
	if _, err := r.GetByName(ctx, "web-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByName after retire: %v", err)
	}
	if list, _, err := r.List(ctx, "", 50, ListFilter{}); err != nil || len(list) != 0 {
		t.Fatalf("List after retire: %d %v", len(list), err)
	}
	if list, err := r.ListByTags(ctx, map[string]string{"env": "prod"}); err != nil || len(list) != 0 {
		t.Fatalf("ListByTags after retire: %d %v", len(list), err)
	}
	if err := r.Update(ctx, tg); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Update of a retired target must be not found, got %v", err)
	}

	// The history still resolves to the machine's name.
	var name string
	if err := db.QueryRowContext(ctx, `SELECT t.name FROM access_sessions s JOIN targets t ON t.id = s.target_id WHERE s.id = 's1'`).Scan(&name); err != nil || name != "web-1" {
		t.Fatalf("session lost its target name: %q %v", name, err)
	}
	var bindings int
	if err := db.QueryRowContext(ctx, db.Rebind(`SELECT COUNT(*) FROM target_credentials WHERE target_id = ?`), tg.ID).Scan(&bindings); err != nil || bindings != 0 {
		t.Fatalf("credential bindings should be dropped, got %d %v", bindings, err)
	}
	// The name is free again, under a new id.
	again := &Target{Name: "web-1", Address: "10.0.0.6", OSFamily: Linux}
	if err := r.Create(ctx, again); err != nil {
		t.Fatalf("re-enrol retired name: %v", err)
	}
	if again.ID == tg.ID {
		t.Fatal("re-enrolment must not reuse the retired id")
	}
	if err := r.Create(ctx, &Target{Name: "web-1", Address: "10.0.0.7", OSFamily: Linux}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("a live name must still be unique, got %v", err)
	}
}
