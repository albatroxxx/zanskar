// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestDirectAccessRequested: a direct message (ADR 0049) goes through the
// gateway's mail server to the people named, one message each so nobody
// reads another's address (review R7), with the approvals link and without
// an event number; with no server set, nothing is sent and the caller hears
// why.
func TestDirectAccessRequested(t *testing.T) {
	port, got := fakeSMTP(t)
	d := &Direct{Sender: &Sender{}, Base: "https://gw.example.com/",
		Server: func(context.Context) (*Server, error) {
			return &Server{Host: "127.0.0.1", Port: port, From: "gw@example.com"}, nil
		}}
	if err := d.AccessRequested(context.Background(), []string{"carol@example.com", "dan@example.com"}, "alice", "ssh", "web-1", "r-1"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var mail string
	for time.Now().Before(deadline) {
		if mail = got(); strings.Count(mail, "Zanskar,") == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, want := range []string{"To: carol@example.com\r\n", "To: dan@example.com\r\n", "alice asks for SSH access to web-1. Open it to approve or deny.", "https://gw.example.com/approvals?request=r-1", "\r\n-- \r\nZanskar, 20"} {
		if !strings.Contains(mail, want) {
			t.Fatalf("the mail lacks %q:\n%s", want, mail)
		}
	}
	if strings.Contains(mail, "carol@example.com, dan@example.com") || strings.Count(mail, "Subject:") != 2 {
		t.Fatalf("one message per recipient, never two addresses in one To:\n%s", mail)
	}
	if strings.Contains(mail, "event") {
		t.Fatalf("a direct message follows no event:\n%s", mail)
	}
	none := &Direct{Sender: &Sender{}, Server: func(context.Context) (*Server, error) { return nil, nil }}
	if err := none.AccessRequested(context.Background(), []string{"x@example.com"}, "a", "ssh", "t", "r"); !errors.Is(err, ErrNoMailServer) {
		t.Fatalf("no server: %v", err)
	}
	if err := d.AccessRequested(context.Background(), nil, "a", "ssh", "t", "r"); err != nil {
		t.Fatalf("nobody to mail: %v", err)
	}
	var nilDirect *Direct
	if err := nilDirect.AccessRequested(context.Background(), []string{"x@example.com"}, "a", "ssh", "t", "r"); !errors.Is(err, ErrNoMailServer) {
		t.Fatalf("nil direct: %v", err)
	}
}
