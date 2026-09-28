// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestMarkersAndTranscript(t *testing.T) {
	cast := `{"version": 2, "width": 80, "height": 24}
[0.5, "o", "$ "]
[1.25, "i", "ls\r"]
[1.3, "m", "ls -la"]
[2.0, "o", "total 0\r\n"]
[65.0, "m", "(hidden input)"]
not an event line
[3661.5, "m", "sudo reboot"]
[3662, "o", "bye"]
`
	ms, err := Markers(strings.NewReader(cast))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 3 || ms[0].Label != "ls -la" || ms[1].Label != "(hidden input)" || ms[2].Label != "sudo reboot" {
		t.Fatalf("markers: %+v", ms)
	}
	if ms[0].At != 1300*time.Millisecond || ms[2].At != 3661500*time.Millisecond {
		t.Fatalf("times: %v %v", ms[0].At, ms[2].At)
	}
	var out bytes.Buffer
	if err := WriteTranscript(&out, []string{"alice on box (SSH)", "started 2026-09-28T10:00:00Z"}, ms); err != nil {
		t.Fatal(err)
	}
	want := "# alice on box (SSH)\n# started 2026-09-28T10:00:00Z\n#\n00:00:01  ls -la\n00:01:05  (hidden input)\n01:01:01  sudo reboot\n"
	if out.String() != want {
		t.Fatalf("transcript:\n%s", out.String())
	}
	out.Reset()
	if err := WriteTranscript(&out, nil, nil); err != nil || !strings.Contains(out.String(), "no command lines") {
		t.Fatalf("empty transcript: %v %q", err, out.String())
	}
}
