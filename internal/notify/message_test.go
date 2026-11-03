// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
)

// TestRequestMessagesLinkToTheRequest (2026-11-03, idea 3): a request's
// message, asked or decided, opens that request in Approvals; the link
// names it and decides nothing (ADR 0039).
func TestRequestMessagesLinkToTheRequest(t *testing.T) {
	names := func(kind, id string) string { return kind + ":" + id }
	at := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		action, id, kind, link string
	}{
		{audit.AccessRequestCreate, "r1", EventAccessRequested, "https://gw.example.com/admin/approvals?request=r1"},
		{audit.AccessRequestApprove, "r2", EventAccessDecided, "https://gw.example.com/admin/approvals?request=r2"},
		{audit.AccessRequestDeny, "r3", EventAccessDecided, "https://gw.example.com/admin/approvals?request=r3"},
		{audit.AccessRequestRevoke, "r4", EventAccessDecided, "https://gw.example.com/admin/approvals?request=r4"},
		// An id is the gateway's own, but the link escapes it all the same.
		{audit.AccessRequestCreate, "a&b=c#d", EventAccessRequested, "https://gw.example.com/admin/approvals?request=a%26b%3Dc%23d"},
	} {
		e := audit.Event{ID: 7, Action: c.action, ObjectType: "access_request", ObjectID: c.id, ActorUserID: "u-bob", Timestamp: at,
			Details: json.RawMessage(`{"target_id":"t1","protocol":"ssh"}`)}
		if k := kindOf(e); k != c.kind {
			t.Fatalf("%s: kind %q, want %q", c.action, k, c.kind)
		}
		m := message(e, c.kind, names, "https://gw.example.com")
		if m.Link != c.link {
			t.Fatalf("%s %s: link %q, want %q", c.action, c.id, m.Link, c.link)
		}
	}
}
