// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/albatroxxx/zanskar/internal/user"
)

func usernames(t *testing.T, r resp) []string {
	t.Helper()
	items, _ := r.body["items"].([]any)
	var out []string
	for _, it := range items {
		out = append(out, it.(map[string]any)["username"].(string))
	}
	return out
}

// TestUsersListPostureFilter (2026-11-04): a dashboard tile opens what it
// counted. The list answers each tile's name with that set, not the whole
// list, whole and unpaged; an unknown name is refused; and a failure
// reading the providers is an error, never an unfiltered list.
func TestUsersListPostureFilter(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, u := range []*user.User{
		{Username: "pw", DisplayName: "Pw", PasswordHash: "hash", Roles: []user.Role{user.RoleUser}},
		{Username: "pw-admin", DisplayName: "Pw Admin", PasswordHash: "hash", Roles: []user.Role{user.RoleAdmin}},
		{Username: "off", DisplayName: "Off", PasswordHash: "hash", Roles: []user.Role{user.RoleUser}, Status: user.StatusDisabled},
	} {
		if err := e.users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
	}

	r := e.do("GET", "/api/v1/users?posture=not_enrolled", nil)
	// root has no password and no provider yet: it cannot sign in, so it needs no authenticator.
	if got := usernames(t, r); r.code != 200 || !slices.Equal(got, []string{"pw", "pw-admin"}) {
		t.Fatalf("not_enrolled: %d %v", r.code, got)
	}
	if r := e.do("GET", "/api/v1/users?posture=admins", nil); !slices.Equal(usernames(t, r), []string{"pw-admin", "root"}) {
		t.Fatalf("admins: %v", usernames(t, r))
	}
	if r := e.do("GET", "/api/v1/users?posture=dormant", nil); r.code != 200 || len(usernames(t, r)) != 0 {
		t.Fatalf("dormant, with everyone new: %d %v", r.code, usernames(t, r))
	}
	if r := e.do("GET", "/api/v1/users?posture=everyone", nil); r.code != 400 {
		t.Fatalf("an unknown posture: %d %v", r.code, r.body)
	}
	if r := e.do("GET", "/api/v1/users", nil); len(usernames(t, r)) != 4 {
		t.Fatalf("no filter lists everyone: %v", usernames(t, r))
	}

	// 2026-11-04: q finds a word in the name, closest first, alone or inside a tile's set.
	if got := usernames(t, e.do("GET", "/api/v1/users?q=pw", nil)); !slices.Equal(got, []string{"pw", "pw-admin"}) {
		t.Fatalf("q=pw: %v", got)
	}
	if got := usernames(t, e.do("GET", "/api/v1/users?q=ADM", nil)); !slices.Equal(got, []string{"pw-admin"}) {
		t.Fatalf("q=ADM (a word inside, any case): %v", got)
	}
	if got := usernames(t, e.do("GET", "/api/v1/users?posture=admins&q=pw", nil)); !slices.Equal(got, []string{"pw-admin"}) {
		t.Fatalf("posture and q: %v", got)
	}
	if got := usernames(t, e.do("GET", "/api/v1/users?q=nobodyhasthis", nil)); len(got) != 0 {
		t.Fatalf("q matching nothing: %v", got)
	}

	e.h.MFAOwners = func(context.Context) ([]string, error) { return nil, errors.New("providers unreadable") }
	if r := e.do("GET", "/api/v1/users?posture=not_enrolled", nil); r.code != 500 {
		t.Fatalf("a provider failure must not answer with a list: %d %v", r.code, r.body)
	}
}
