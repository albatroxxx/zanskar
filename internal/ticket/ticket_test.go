// SPDX-License-Identifier: Apache-2.0

package ticket

import (
	"errors"
	"testing"
	"time"
)

func TestIssueRedeem(t *testing.T) {
	s := NewStore()
	base := time.Now()
	s.now = func() time.Time { return base }
	tok, err := s.Issue(Grant{UserID: "u1", TargetID: "t1", Protocol: "ssh", ClientIP: "10.0.0.1", UserSecret: []byte("pw")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(tok, "10.0.0.2"); !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong IP must be refused")
	}
	if s.Len() != 0 {
		t.Fatal("a failed redeem must still consume the ticket")
	}
	tok, _ = s.Issue(Grant{UserID: "u1", ClientIP: "10.0.0.1"})
	g, err := s.Redeem(tok, "10.0.0.1")
	if err != nil || g.UserID != "u1" {
		t.Fatalf("redeem: %v", err)
	}
	if _, err := s.Redeem(tok, "10.0.0.1"); !errors.Is(err, ErrInvalid) {
		t.Fatal("second redeem must fail")
	}
	tok, _ = s.Issue(Grant{ClientIP: "10.0.0.1"})
	s.now = func() time.Time { return base.Add(TTL + time.Second) }
	if _, err := s.Redeem(tok, "10.0.0.1"); !errors.Is(err, ErrInvalid) {
		t.Fatal("expired ticket must fail")
	}
	if _, err := s.Redeem("nope", "10.0.0.1"); !errors.Is(err, ErrInvalid) {
		t.Fatal("unknown ticket must fail")
	}
}
