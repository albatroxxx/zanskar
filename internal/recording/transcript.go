// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Marker is one annotation in an asciicast: the gateway writes one per
// command line the user submitted, with "(hidden input)" standing in for
// text the remote did not echo, such as a password, which is never stored.
type Marker struct {
	At    time.Duration
	Label string
}

// Markers reads the marker events out of an asciicast v2 stream, in order.
// Other events are skipped, as are lines that are not events (the header,
// a truncated tail); a transcript is best effort over whatever was recorded.
func Markers(r io.Reader) ([]Marker, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []Marker
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || line[0] != '[' {
			continue
		}
		var ev []json.RawMessage
		if err := json.Unmarshal(line, &ev); err != nil || len(ev) < 3 {
			continue
		}
		var kind string
		if err := json.Unmarshal(ev[1], &kind); err != nil || kind != "m" {
			continue
		}
		var at float64
		var label string
		if err := json.Unmarshal(ev[0], &at); err != nil {
			continue
		}
		if err := json.Unmarshal(ev[2], &label); err != nil {
			continue
		}
		out = append(out, Marker{At: time.Duration(at * float64(time.Second)), Label: label})
	}
	return out, sc.Err()
}

// WriteTranscript renders markers as a plain-text command transcript: a
// short header, then one "HH:MM:SS  command" line each. It is what an
// auditor hands to someone who will never open the player.
func WriteTranscript(w io.Writer, header []string, markers []Marker) error {
	var b strings.Builder
	for _, h := range header {
		b.WriteString("# " + h + "\n")
	}
	if len(header) > 0 {
		b.WriteString("#\n")
	}
	if len(markers) == 0 {
		b.WriteString("# no command lines were recorded in this session\n")
	}
	for _, m := range markers {
		s := int(m.At / time.Second)
		fmt.Fprintf(&b, "%02d:%02d:%02d  %s\n", s/3600, (s%3600)/60, s%60, m.Label)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
