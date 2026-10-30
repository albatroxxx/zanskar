// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/policy/policytest"
	"github.com/albatroxxx/zanskar/internal/protocol"
)

// TestSignInPerGrant (ADR 0036): a grant says how a person signs in. When
// every deciding grant says own, connect asks for the person's own login
// although the target's slot holds a vaulted credential; when a grant lets
// the slot decide, the slot's credential is used, and a person who brings
// their own login where a grant allows it gets it used instead. The portal
// lists where the own login is allowed.
func TestSignInPerGrant(t *testing.T) {
	f := newConnectFixture(t)
	redeem := func(body map[string]any) (code string, username string, own bool) {
		t.Helper()
		status, out := f.connect(t, body)
		if status != http.StatusOK {
			c, _ := out["code"].(string)
			return c, "", false
		}
		g, err := f.h.Tickets.Redeem(out["ticket"].(string), "203.0.113.5", f.sessionID)
		if err != nil {
			t.Fatal(err)
		}
		defer g.Wipe()
		return "", g.Username, len(g.UserSecret) > 0 && g.CredentialID == ""
	}
	ok := map[string]any{"target_id": f.ids["ok"], "protocol": "ssh"}
	withLogin := map[string]any{"target_id": f.ids["ok"], "protocol": "ssh", "credential": map[string]string{"username": "alice-own", "password": "hers"}}

	// As the fixture stands, test-all lets the slot decide: the vaulted
	// credential is used, and a login brought along is ignored.
	if code, _, own := redeem(ok); code != "" || own {
		t.Fatalf("slot decides: code %q, own %v", code, own)
	}
	if code, _, own := redeem(withLogin); code != "" || own {
		t.Fatalf("an own login where no grant allows it was used: code %q, own %v", code, own)
	}

	// Every grant that decides says own: the person's login is asked for.
	p, err := f.h.Policies.Get(f.ctx, f.policyIDs["test-all"])
	if err != nil {
		t.Fatal(err)
	}
	for i := range p.Grants {
		if p.Grants[i].Kind == protocol.KindHost {
			p.Grants[i].SignIn = policy.SignInOwn
		}
	}
	if err := f.h.Policies.Update(f.ctx, p); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := redeem(ok); code != "credential_required" {
		t.Fatalf("own only, no login given: %q, want credential_required", code)
	}
	if code, user, own := redeem(withLogin); code != "" || !own || user != "alice-own" {
		t.Fatalf("own only, login given: code %q user %q own %v", code, user, own)
	}

	// Both allowed: the slot by default, the person's login when brought.
	both := policytest.Policy("slot-too", []policy.Subject{policytest.User(f.alice.ID)},
		policytest.Tagged(protocol.KindHost, map[string]string{"env": "test"}, "ssh"))
	if err := f.h.Policies.Create(f.ctx, both); err != nil {
		t.Fatal(err)
	}
	if code, _, own := redeem(ok); code != "" || own {
		t.Fatalf("both, nothing brought: code %q own %v", code, own)
	}
	if code, user, own := redeem(withLogin); code != "" || !own || user != "alice-own" {
		t.Fatalf("both, login brought: code %q user %q own %v", code, user, own)
	}
	rr := f.do("GET", "/api/v1/me/targets", "", nil, f.cookie, f.csrf)
	page := decodeTargets(t, rr.Body.Bytes())
	for _, it := range page {
		if it.Name == "ok" && !slices.Contains(it.OwnLogin, "ssh") {
			t.Fatalf("the portal does not offer the own login: %+v", it)
		}
	}
}

func decodeTargets(t *testing.T, body []byte) []reachableTarget {
	t.Helper()
	var page struct {
		Items []reachableTarget `json:"items"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	return page.Items
}
