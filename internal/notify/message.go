// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/albatroxxx/zanskar/internal/audit"
)

// The kinds of event a channel can ask for (ADR 0039).
const (
	EventAccessRequested   = "access_requested"
	EventAccessDecided     = "access_decided"
	EventSessionTerminated = "session_terminated"
	EventProviderFailing   = "provider_failing"
	EventRecordingLost     = "recording_lost"
	EventDiskFull          = "disk_full"
)

// Events lists every kind, in the order the console offers them.
var Events = []string{EventAccessRequested, EventAccessDecided, EventSessionTerminated, EventProviderFailing, EventRecordingLost, EventDiskFull}

// kindOf is the kind of notification an audit event is, or "" for one no
// channel is told about.
func kindOf(e audit.Event) string {
	switch e.Action {
	case audit.AccessRequestCreate:
		return EventAccessRequested
	case audit.AccessRequestApprove, audit.AccessRequestDeny, audit.AccessRequestRevoke:
		return EventAccessDecided
	case audit.SessionTerminate:
		return EventSessionTerminated
	case audit.IdPSync:
		if e.Outcome == audit.Failure {
			return EventProviderFailing
		}
	case audit.RecordingLost:
		return EventRecordingLost
	case audit.SessionConnect:
		if e.Outcome == audit.Failure && detail(e, "reason") == "disk_full" {
			return EventDiskFull
		}
	}
	return ""
}

// Message is one notification: a subject line, the sentence, and the page
// of the console that acts on it.
type Message struct {
	Kind    string
	EventID int64
	At      string
	Subject string
	Text    string
	Link    string
}

// Names resolves ids to names by kind ("user", "target", "identity_provider",
// ...), as the Events page does; a missing name falls back to a short id.
type Names func(kind, id string) string

func detail(e audit.Event, key string) string {
	var d map[string]any
	if json.Unmarshal(e.Details, &d) != nil {
		return ""
	}
	if s, ok := d[key].(string); ok {
		return s
	}
	return ""
}

// clean makes a value safe for one line of a subject or a sentence: no line
// breaks (a header injected into an email), no control characters.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// message words an event of kind for a person, with the console's address
// base (the public URL) for its link.
func message(e audit.Event, kind string, names Names, base string) Message {
	who := names("user", e.ActorUserID)
	if e.ActorUserID == "" {
		who = "the gateway"
	}
	target := names("target", detail(e, "target_id"))
	if target == "" {
		target = names("autoscaling_group", detail(e, "asg_id"))
	}
	proto := strings.ToUpper(detail(e, "protocol"))
	m := Message{Kind: kind, EventID: e.ID, At: e.Timestamp.UTC().Format("2006-01-02 15:04 UTC")}
	switch kind {
	case EventAccessRequested:
		m.Subject = fmt.Sprintf("%s asks for %s access to %s", who, proto, target)
		m.Text = m.Subject + ". Approve or deny it in the console."
		m.Link = base + "/admin/approvals"
	case EventAccessDecided:
		verb := map[string]string{audit.AccessRequestApprove: "approved", audit.AccessRequestDeny: "denied", audit.AccessRequestRevoke: "revoked"}[e.Action]
		m.Subject = fmt.Sprintf("%s %s %s access to %s", who, verb, proto, target)
		m.Text = m.Subject + "."
		m.Link = base + "/admin/approvals"
	case EventSessionTerminated:
		m.Subject = fmt.Sprintf("%s ended a session", who)
		m.Text = m.Subject + "."
		m.Link = base + "/admin/sessions"
	case EventProviderFailing:
		provider := names("identity_provider", e.ObjectID)
		m.Subject = fmt.Sprintf("Sign-in provider %s failed its sync", provider)
		m.Text = m.Subject + ": " + detail(e, "error") + ". Single sign-on may be down."
		m.Link = base + "/admin/identity-providers"
	case EventRecordingLost:
		m.Subject = "A session's recording was lost"
		m.Text = m.Subject + ": " + detail(e, "error") + "."
		m.Link = base + "/admin/recordings"
	case EventDiskFull:
		m.Subject = "New sessions are refused: the gateway's disk is full"
		m.Text = m.Subject + ". Free space on the gateway; running sessions go on."
		m.Link = base + "/admin"
	}
	m.Subject, m.Text = clean(m.Subject), clean(m.Text)
	return m
}
