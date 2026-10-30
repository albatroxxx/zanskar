// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/albatroxxx/zanskar/internal/audit"
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

// oldImages is the reaper's second job (2026-10-30): when the setting allows,
// it removes earlier versions' browser and relay images from the host and
// records what went, once per pass that removed something.
type oldImages struct {
	Enabled    func() bool
	Configured func() []string
	// Remove is containers.RemoveOldImages, a stand-in in tests.
	Remove func(ctx context.Context, configured []string) ([]string, error)
	Audit  interface {
		Record(ctx context.Context, e audit.Event) (audit.Event, error)
	}
	Log    *slog.Logger
	notice reapNotice
}

// releasedBuild reports whether v is a released version. A development
// build's default images are the published ones at latest, so on a
// developer's host every released image would count as an earlier version's:
// a development build removes nothing.
func releasedBuild(v string) bool {
	v = strings.TrimPrefix(v, "v")
	return v != "" && v != "dev"
}

func (o *oldImages) pass(ctx context.Context) {
	if o.Enabled != nil && !o.Enabled() {
		return
	}
	removed, err := o.Remove(ctx, o.Configured())
	if len(removed) > 0 {
		o.Log.Info("removed earlier versions' images from the host", "images", removed)
		if o.Audit != nil {
			_, _ = o.Audit.Record(ctx, audit.Actor{IP: "system"}.Event(audit.SystemImagesRemove, "system", "gateway", audit.Success, map[string]any{"images": removed}))
		}
	}
	if level, ok := o.notice.level(err); ok {
		o.Log.Log(ctx, level, "cannot remove earlier versions' images from the host", "err", err)
	}
}
