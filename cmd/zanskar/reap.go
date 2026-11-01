// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"slices"
	"strings"
	"sync"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/target"
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

// warmImages is the reaper's third job (2026-11-01): it pulls the images the
// enrolled targets' sessions will need, so the first application session
// after an upgrade does not wait minutes on the new browser image (the live
// console: "Container images 0 B" on its dashboard, and every first session
// after an upgrade waiting on the pull). It runs after the old images went,
// the order a nearly full disk needs, and only for images a session would
// pull anyway.
type warmImages struct {
	Enabled func() bool
	// Needed is the images sessions to the enrolled targets will need.
	Needed func(ctx context.Context) ([]string, error)
	// Ensure is containers.EnsureImage, a stand-in in tests.
	Ensure func(ctx context.Context, image string) error
	Log    *slog.Logger
	notice reapNotice
	// busy keeps passes from overlapping: a pull takes minutes on a slow
	// link, and the reaper does not wait for it.
	busy sync.Mutex
}

// neededImages is the images sessions to inv's targets will pull: an
// application's browser and the relay beside it; for a MySQL or MariaDB
// database, the relay (the gateway's own image) as its sidecar. A database's
// client image follows the database's version, not the gateway's, so an
// upgrade leaves it in place and it is not pulled ahead.
func neededImages(inv target.Inventory, browser, relay string) []string {
	var out []string
	add := func(img string) {
		if img != "" && !slices.Contains(out, img) {
			out = append(out, img)
		}
	}
	if inv.Applications > 0 {
		add(relay)
		add(browser)
	}
	if inv.ByEngine[protocol.MySQL]+inv.ByEngine[protocol.MariaDB] > 0 {
		add(relay)
	}
	return out
}

func (w *warmImages) pass(ctx context.Context) {
	if w.Enabled != nil && !w.Enabled() {
		return
	}
	if !w.busy.TryLock() {
		return // an earlier pass is still pulling
	}
	defer w.busy.Unlock()
	images, err := w.Needed(ctx)
	for _, img := range images {
		if err != nil {
			break
		}
		err = w.Ensure(ctx, img)
	}
	if ctx.Err() != nil {
		return // shutting down: a pull cut short says nothing about Docker
	}
	if level, ok := w.notice.level(err); ok {
		w.Log.Log(ctx, level, "cannot pull the images sessions will need ahead of the first one", "err", err)
	}
}
