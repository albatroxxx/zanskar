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
	"github.com/albatroxxx/zanskar/internal/target"
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

// TestNeededImages (2026-11-01): an application needs the browser and the
// relay beside it, a MySQL or MariaDB database the relay as its sidecar; a
// gateway with neither pulls nothing ahead.
func TestNeededImages(t *testing.T) {
	inv := func(apps int, engines map[string]int) target.Inventory {
		return target.Inventory{Applications: apps, ByEngine: engines}
	}
	for _, c := range []struct {
		name string
		inv  target.Inventory
		want []string
	}{
		{"nothing enrolled", inv(0, nil), nil},
		{"hosts and a postgres database only", inv(0, map[string]int{"postgres": 2}), nil},
		{"an application", inv(1, nil), []string{"relay:1", "browser:1"}},
		{"a mysql database", inv(0, map[string]int{"mysql": 1}), []string{"relay:1"}},
		{"a mariadb database and an application, the relay once", inv(2, map[string]int{"mariadb": 1}), []string{"relay:1", "browser:1"}},
	} {
		if got := neededImages(c.inv, "browser:1", "relay:1"); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if got := neededImages(inv(1, nil), "", ""); got != nil {
		t.Errorf("an unset image is never pulled: %v", got)
	}
}

// TestWarmImagesPass: the pass pulls what is needed in order and stops at
// the first failure, says a failure once, does nothing on a development
// build, and never runs beside a pass still pulling.
func TestWarmImagesPass(t *testing.T) {
	var pulled []string
	var fail error
	enabled := true
	var logged strings.Builder
	w := &warmImages{
		Enabled: func() bool { return enabled },
		Needed:  func(context.Context) ([]string, error) { return []string{"relay:1", "browser:1"}, nil },
		Ensure: func(_ context.Context, img string) error {
			pulled = append(pulled, img)
			return fail
		},
		Log: slog.New(slog.NewTextHandler(&logged, nil)),
	}
	w.pass(context.Background())
	if !slices.Equal(pulled, []string{"relay:1", "browser:1"}) || logged.Len() != 0 {
		t.Fatalf("pulled %v, logged %q", pulled, logged.String())
	}

	pulled, fail = nil, errors.New("permission denied while trying to connect to the docker API")
	w.pass(context.Background())
	w.pass(context.Background())
	if !slices.Equal(pulled, []string{"relay:1", "relay:1"}) {
		t.Fatalf("a failed pull ends the pass: %v", pulled)
	}
	if n := strings.Count(logged.String(), "level=WARN"); n != 1 {
		t.Fatalf("a failure is a warning once, then quiet: %q", logged.String())
	}

	enabled, pulled = false, nil
	w.pass(context.Background())
	if pulled != nil {
		t.Fatalf("a development build pulled %v", pulled)
	}

	// A pass that finds another still pulling leaves it be.
	enabled, fail, pulled = true, nil, nil
	hold, release := make(chan struct{}), make(chan struct{})
	w.Ensure = func(_ context.Context, img string) error {
		pulled = append(pulled, img)
		if img == "relay:1" {
			close(hold)
			<-release
		}
		return nil
	}
	done := make(chan struct{})
	go func() {
		w.pass(context.Background())
		close(done)
	}()
	<-hold
	w.pass(context.Background())
	close(release)
	<-done
	if !slices.Equal(pulled, []string{"relay:1", "browser:1"}) {
		t.Fatalf("two passes ran at once: %v", pulled)
	}
}
