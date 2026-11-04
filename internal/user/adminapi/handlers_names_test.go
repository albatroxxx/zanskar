// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/user"
)

// TestADisplayNameCannotHideWhatItIs (2026-11-04, live walkthrough of 1.18.4):
// a name with a newline, a bell or a right-to-left override reads as something
// else in lists and audit sentences. Creating or changing an account with one
// is refused, and the message names the rule.
func TestADisplayNameCannotHideWhatItIs(t *testing.T) {
	e := newEnv(t)
	for label, name := range map[string]string{
		"newline":  "Ann\nBee",
		"bell":     "Ann" + string(rune(7)) + "Bee",
		"override": "Ann" + string(rune(0x202E)) + "txt.exe",
		"zero":     "Ann" + string(rune(0x200B)) + "Bee",
	} {
		r := e.do("POST", "/api/v1/users", map[string]any{"username": "ann.bee", "display_name": name, "roles": []string{"user"}})
		if msg, _ := r.body["message"].(string); r.code != 400 || !strings.HasPrefix(msg, "name must not contain") {
			t.Errorf("%s: create answered %d %v", label, r.code, r.body)
		}
	}

	ctx := context.Background()
	u := &user.User{Username: "plain", DisplayName: "Plain", Roles: []user.Role{user.RoleUser}}
	if err := e.users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	r := e.do("PUT", "/api/v1/users/"+u.ID, map[string]any{"display_name": "Plain" + string(rune(0x202E)) + "gpj.exe"})
	if msg, _ := r.body["message"].(string); r.code != 400 || !strings.HasPrefix(msg, "name must not contain") {
		t.Errorf("update answered %d %v", r.code, r.body)
	}
	if got, _ := e.users.GetByID(ctx, u.ID); got.DisplayName != "Plain" {
		t.Errorf("the refused change was kept: %q", got.DisplayName)
	}
	// A name in any script, with its joiners, is welcome.
	ok := e.do("PUT", "/api/v1/users/"+u.ID, map[string]any{"display_name": "Zurich B" + string(rune(0xFC)) + "ro"})
	if ok.code != 200 {
		t.Errorf("a plain accented name: %d %v", ok.code, ok.body)
	}
}
