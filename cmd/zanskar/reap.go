// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"log/slog"
	"os/exec"
)

// reapNotice decides how loudly each pass of the database session reaper
// reports a failure. A host with no container CLI serves no database targets,
// so that is only a debug line. A CLI the service user may not use is a warning
// once: it would otherwise repeat every five minutes for as long as the host is
// misconfigured, and once it has been said, the repeats are debug lines until a
// pass works again.
type reapNotice struct{ failing bool }

// level is the level to log a pass that ended with err at, and false when the
// pass worked and there is nothing to say.
func (n *reapNotice) level(err error) (slog.Level, bool) {
	switch {
	case err == nil:
		n.failing = false
		return 0, false
	case errors.Is(err, exec.ErrNotFound), n.failing:
		return slog.LevelDebug, true
	default:
		n.failing = true
		return slog.LevelWarn, true
	}
}
