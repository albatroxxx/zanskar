// SPDX-License-Identifier: Apache-2.0

package apprelay

import (
	"strings"
	"testing"
)

// TestParseRefusals: the relay's refusal lines come back as values, in
// order, from among the container's other log lines; a malformed line, a
// line of another kind and one without a port are passed over.
func TestParseRefusals(t *testing.T) {
	log := strings.Join([]string{
		`{"time":"2026-11-03T10:00:00Z","level":"INFO","msg":"apprelay proxy listening","addr":"172.18.0.2:3128"}`,
		`{"time":"2026-11-03T10:00:01Z","level":"INFO","msg":"apprelay refused","host":"cdn.corp","port":"443","why":"private","what":"script","from":"http://wiki.corp","count":3}`,
		`not json at all`,
		`{"time":"2026-11-03T10:00:02Z","level":"INFO","msg":"apprelay refused","host":"169.254.169.254","port":"80","why":"link-local","what":"image","from":"http://wiki.corp","count":1}`,
		`{"time":"2026-11-03T10:00:03Z","level":"INFO","msg":"apprelay refused","host":"x","port":"nope","why":"private","what":"script","from":"","count":1}`,
		`{"time":"2026-11-03T10:00:04Z","level":"INFO","msg":"apprelay refused","host":"api.corp","port":"8443","why":"private","what":"empty","from":"","count":0}`,
	}, "\n")
	got := ParseRefusals(strings.NewReader(log))
	if len(got) != 3 {
		t.Fatalf("parsed %d refusals: %+v", len(got), got)
	}
	if got[0] != (Refused{Host: "cdn.corp", Port: 443, Why: "private", What: "script", From: "http://wiki.corp", Count: 3, At: got[0].At}) || got[0].At.IsZero() {
		t.Errorf("first: %+v", got[0])
	}
	if got[1].Host != "169.254.169.254" || got[1].Why != "link-local" || got[2].Port != 8443 || got[2].Count != 1 {
		t.Errorf("others: %+v %+v", got[1], got[2])
	}
}
