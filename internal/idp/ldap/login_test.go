// SPDX-License-Identifier: Apache-2.0

package ldap

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/idp"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// TestLoginAdoptsPreCreatedAccount is H8 through a real directory bind: the
// administrator created alice with no password and auto-provisioning is off.
// Her first sign-in links the account to the provider and her entryUUID.
func TestLoginAdoptsPreCreatedAccount(t *testing.T) {
	fd := startFakeDirectory(t)
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	kek, _ := crypto.NewLocalKEK(bytes.Repeat([]byte{7}, 32))
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	repo, users := idp.NewRepo(db, ring), user.NewRepo(db)
	p := &idp.Provider{Name: "corp", Type: idp.TypeLDAP, Enabled: true}
	if err := repo.Create(ctx, p, &idp.Config{LDAP: baseConfig(fd)}); err != nil {
		t.Fatal(err)
	}
	alice := &user.User{Username: "alice", DisplayName: "Alice", Roles: []user.Role{user.RoleAuditor}}
	if err := users.Create(ctx, alice); err != nil {
		t.Fatal(err)
	}
	auditLog := audit.NewLog(db)
	l := NewLogin(repo, &idp.Provisioner{Users: users}, auditLog, nil)
	l.Auth = &Authenticator{Timeout: 3 * time.Second}
	links := func() []audit.Event {
		t.Helper()
		evs, _, err := auditLog.List(ctx, audit.Filter{Action: "user.link", Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		return evs
	}

	u, err := l.Login(ctx, "alice", alicePW, "203.0.113.9")
	if err != nil {
		t.Fatalf("first directory sign-in of a pre-created account: %v", err)
	}
	if u.ID != alice.ID || u.IdPID != p.ID || u.ExternalID != "uuid:"+strings.ToLower(aliceUUID) {
		t.Fatalf("got %s linked to %q/%q, want account %s linked to the directory entry", u.ID, u.IdPID, u.ExternalID, alice.ID)
	}
	if len(u.Roles) != 1 || u.Roles[0] != user.RoleAuditor {
		t.Fatalf("roles %v: adoption keeps the administrator's", u.Roles)
	}
	evs := links()
	if len(evs) != 1 {
		t.Fatalf("%d user.link events, want 1", len(evs))
	}
	var d map[string]string
	_ = json.Unmarshal(evs[0].Details, &d)
	if ev := evs[0]; ev.ActorUserID != alice.ID || ev.ActorIP != "203.0.113.9" || ev.ObjectID != alice.ID || ev.Outcome != audit.Success ||
		d["idp"] != p.ID || d["idp_name"] != "corp" || d["external_id"] != u.ExternalID {
		t.Fatalf("user.link event: %+v %v", ev, d)
	}

	// The second sign-in matches on the entryUUID and links nothing.
	if again, err := l.Login(ctx, "alice", alicePW, "203.0.113.9"); err != nil || again.ID != alice.ID {
		t.Fatalf("second sign-in: %v %v", again, err)
	}
	if n := len(links()); n != 1 {
		t.Fatalf("%d user.link events after the second sign-in, want still 1", n)
	}
}
