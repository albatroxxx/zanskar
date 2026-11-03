// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// cast builds an asciicast v2 stream from (time, kind, data) events.
func cast(events ...any) string {
	var b strings.Builder
	b.WriteString(`{"version":2,"width":80,"height":24}` + "\n")
	for i := 0; i+2 < len(events); i += 3 {
		line, _ := json.Marshal([]any{events[i], events[i+1], events[i+2]})
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func texts(lines []OutputLine) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l.Text
	}
	return out
}

func TestOutputLinesReadWhatAPersonSaw(t *testing.T) {
	s := cast(
		0.5, "o", "\x1b[1;32mroot@web-1\x1b[0m:~# ",
		0.9, "m", "systemctl status nginx",
		1.0, "o", "systemctl status nginx\r\n",
		1.2, "o", "\x1b]0;root@web-1: ~\x07● nginx.service - A high perf",
		1.3, "o", "ormance web server\r\n   Active: \x1b[0;1;31mfailed\x1b[0m (Result: exit-code)\r\n",
		// A progress bar rewrites its line; only where it ended is kept.
		2.0, "o", "Downloading  10%\rDownloading  55%\rDownloading 100%\r\n",
		// Backspace, a tab, a charset switch and an unfinished CSI split
		// across events.
		3.0, "o", "lss\b -la\tdone\x1b(B\x1b[",
		3.1, "o", "0m\r\n",
		// Blank, one-character and repeated lines say nothing new.
		4.0, "o", "\r\n   \r\n$\r\nsame line\r\nsame line\r\n",
		// A last line without a newline is kept.
		5.0, "o", "logout",
	)
	markers, lines, truncated, err := Index(strings.NewReader(s), 100)
	if err != nil || truncated {
		t.Fatal(err, truncated)
	}
	want := []string{
		"root@web-1:~# systemctl status nginx",
		"● nginx.service - A high performance web server",
		"   Active: failed (Result: exit-code)",
		"Downloading 100%",
		"ls -la done",
		"same line",
		"logout",
	}
	if got := texts(lines); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("lines:\n got %q\nwant %q", got, want)
	}
	if len(markers) != 1 || markers[0].Label != "systemctl status nginx" {
		t.Fatalf("markers from the same read: %+v", markers)
	}
	// Each line is timed by its first character.
	if lines[0].At != 500*time.Millisecond || lines[1].At != 1200*time.Millisecond || lines[6].At != 5*time.Second {
		t.Fatalf("times: %v %v %v", lines[0].At, lines[1].At, lines[6].At)
	}
}

func TestOutputLinesAreBounded(t *testing.T) {
	var events []any
	for i := 0; i < 30; i++ {
		events = append(events, float64(i), "o", "line number "+strings.Repeat("x", i)+"\r\n")
	}
	events = append(events, 31.0, "m", "after the cap")
	_, lines, truncated, err := Index(strings.NewReader(cast(events...)), 10)
	if err != nil || len(lines) != 10 || !truncated {
		t.Fatalf("10 kept of 30: %d %v %v", len(lines), truncated, err)
	}
	markers, _, _, _ := Index(strings.NewReader(cast(events...)), 10)
	if len(markers) != 1 {
		t.Fatal("markers are read past the output cap")
	}
	// One line is cut at MaxOutputLine bytes, on a character boundary.
	long := strings.Repeat("é", MaxOutputLine) + "\r\n"
	_, lines, _, _ = Index(strings.NewReader(cast(0.1, "o", long)), 10)
	if len(lines) != 1 || len(lines[0].Text) > MaxOutputLine || !strings.HasPrefix(long, lines[0].Text) {
		t.Fatalf("long line: %d bytes", len(lines[0].Text))
	}
	// Exactly the cap is not truncated.
	_, lines, truncated, _ = Index(strings.NewReader(cast(0.1, "o", "aa\r\nbb\r\n")), 2)
	if len(lines) != 2 || truncated {
		t.Fatalf("two of two: %d %v", len(lines), truncated)
	}
	// maxLines 0 reads markers only.
	_, lines, _, _ = Index(strings.NewReader(cast(0.1, "o", "aa\r\n")), 0)
	if len(lines) != 0 {
		t.Fatal("no output read with maxLines 0")
	}
}

func TestOutputLinesSkipBrokenEvents(t *testing.T) {
	s := `{"version":2}` + "\n" + `[1.0, "o", "good line\r\n"]` + "\n" + `[oops` + "\n" + `[2.0, "o"]` + "\n" + `[3.0, "i", "typed\r\n"]` + "\n" + `[4.0, "o", "second\r\n"]` + "\n"
	lines, _, err := OutputLines(strings.NewReader(s), 10)
	if err != nil || strings.Join(texts(lines), "|") != "good line|second" {
		t.Fatalf("got %q %v", texts(lines), err)
	}
}
