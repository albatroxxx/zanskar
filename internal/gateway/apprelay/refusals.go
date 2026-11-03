// SPDX-License-Identifier: Apache-2.0

package apprelay

import (
	"bufio"
	"encoding/json"
	"io"
	"strconv"
	"time"
)

// Refused is one line of the relay's log saying what its proxy refused
// (ADR 0037, amended 2026-11-03, later): the destination, why, what asked
// for it (the browser's fetch destination: script, image, iframe, document)
// and the page's origin, with how many times since the line before.
type Refused struct {
	Host  string
	Port  int
	Why   string
	What  string
	From  string
	Count int
	At    time.Time
}

// refusedMsg is the message the proxy logs a refusal under.
const refusedMsg = "apprelay refused"

// ParseRefusals reads the relay's log as the container runtime gives it
// (slog's JSON lines, other lines among them) and returns its refusals in
// order. A line that is not one, or does not parse, is passed over.
func ParseRefusals(r io.Reader) []Refused {
	var out []Refused
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var line struct {
			Time  time.Time `json:"time"`
			Msg   string    `json:"msg"`
			Host  string    `json:"host"`
			Port  string    `json:"port"`
			Why   string    `json:"why"`
			What  string    `json:"what"`
			From  string    `json:"from"`
			Count int       `json:"count"`
		}
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil || line.Msg != refusedMsg || line.Host == "" {
			continue
		}
		port, err := strconv.Atoi(line.Port)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		if line.Count < 1 {
			line.Count = 1
		}
		out = append(out, Refused{Host: line.Host, Port: port, Why: line.Why, What: line.What, From: line.From, Count: line.Count, At: line.Time})
	}
	return out
}
