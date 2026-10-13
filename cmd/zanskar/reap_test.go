// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"testing"
)

// TestReapNoticeWarnsOnce: a reaper that cannot list containers warns once,
// says the rest at debug, and warns again only after a pass that worked; a
// host with no container CLI is never a warning. It used to warn every five
// minutes for as long as the service user could not use Docker.
func TestReapNoticeWarnsOnce(t *testing.T) {
	denied := errors.New("permission denied while trying to connect to the docker API")
	missing := fmt.Errorf("dbgw: list: %w", exec.ErrNotFound)
	var n reapNotice
	for i, step := range []struct {
		err    error
		logged bool
		level  slog.Level
	}{
		{missing, true, slog.LevelDebug},
		{denied, true, slog.LevelWarn},
		{denied, true, slog.LevelDebug},
		{denied, true, slog.LevelDebug},
		{nil, false, 0},
		{denied, true, slog.LevelWarn},
	} {
		level, logged := n.level(step.err)
		if logged != step.logged || (logged && level != step.level) {
			t.Errorf("pass %d (%v): logged %v at %v, want %v at %v", i+1, step.err, logged, level, step.logged, step.level)
		}
	}
}
