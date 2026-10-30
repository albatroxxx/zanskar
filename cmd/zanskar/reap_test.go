// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
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

type fakeAudit struct{ events []audit.Event }

func (f *fakeAudit) Record(_ context.Context, e audit.Event) (audit.Event, error) {
	f.events = append(f.events, e)
	return e, nil
}

// TestOldImagesPass (2026-10-30): the pass asks for the configured images to
// be kept, records one audit event naming what went, records nothing when
// nothing went, and does nothing at all when the setting is off.
func TestOldImagesPass(t *testing.T) {
	var asked [][]string
	removed := []string{"ghcr.io/albatroxxx/zanskar-browser:1.8.0"}
	var fail error
	enabled := true
	rec := &fakeAudit{}
	o := &oldImages{
		Enabled:    func() bool { return enabled },
		Configured: func() []string { return []string{"browser:1.9.0", "relay:1.9.0"} },
		Remove: func(_ context.Context, configured []string) ([]string, error) {
			asked = append(asked, configured)
			return removed, fail
		},
		Audit: rec, Log: slog.New(slog.DiscardHandler),
	}
	o.pass(context.Background())
	if len(asked) != 1 || !slices.Equal(asked[0], []string{"browser:1.9.0", "relay:1.9.0"}) {
		t.Fatalf("asked to keep %v", asked)
	}
	if len(rec.events) != 1 || rec.events[0].Action != audit.SystemImagesRemove || !strings.Contains(string(rec.events[0].Details), "zanskar-browser:1.8.0") {
		t.Fatalf("events %+v", rec.events)
	}
	removed, fail = nil, errors.New("permission denied")
	o.pass(context.Background())
	if len(rec.events) != 1 {
		t.Fatalf("a pass that removed nothing was recorded: %+v", rec.events)
	}
	enabled = false
	o.pass(context.Background())
	if len(asked) != 2 {
		t.Fatalf("the pass ran with the setting off: %v", asked)
	}
	// A development build removes nothing: its default images are the
	// published ones at latest, and every released one would look old.
	for v, want := range map[string]bool{"v1.9.0": true, "1.9.0-rc.1": true, "dev": false, "": false} {
		if got := releasedBuild(v); got != want {
			t.Errorf("releasedBuild(%q) = %v, want %v", v, got, want)
		}
	}
}
