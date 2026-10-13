// SPDX-License-Identifier: Apache-2.0

package dbgw

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
)

// Labels on every Docker object a session creates, so leftovers are found
// by label and never by guessing names.
const (
	labelManaged = "zanskar.managed"
	labelSession = "zanskar.session"
)

// reapMinAge is how old an object must be before Reap may remove it, so a
// session still starting is never torn down under it.
const reapMinAge = 2 * time.Minute

// createdLayout is how `docker ps` and `docker network ls` print CreatedAt
// ("2026-10-11 15:03:56 +0530 IST"); the network listing adds fractional
// seconds, which Parse accepts without them in the layout.
const createdLayout = "2006-01-02 15:04:05 -0700 MST"

// listFormat has both listings print one object per line: id, session, created.
const listFormat = `{{.ID}}\t{{.Label "` + labelSession + `"}}\t{{.CreatedAt}}`

// runFunc runs one docker command and returns its combined output.
type runFunc func(ctx context.Context, args ...string) (string, error)

// Reap removes the containers and networks of database sessions this gateway
// no longer runs: what a crashed process or a failed teardown left behind
// (ADR 0017). It finds them by label, keeps every object whose session live
// reports running, and leaves objects younger than two minutes alone so a
// session still starting is never torn down under it. Containers go first,
// since a network cannot be removed while one is attached. It returns how
// many objects it removed; a removal that fails is reported and the rest go
// on. docker is the path to the docker CLI, empty for "docker" on PATH.
func Reap(ctx context.Context, docker string, live func(sessionID string) bool) (removed int, err error) {
	if docker == "" {
		docker = "docker"
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	run := func(ctx context.Context, args ...string) (string, error) {
		return dockerOutput(ctx, docker, nil, args...)
	}
	return reap(ctx, run, live, time.Now())
}

// reap is Reap over an injectable runner and clock.
func reap(ctx context.Context, run runFunc, live func(string) bool, now time.Time) (int, error) {
	kinds := []struct{ list, rm []string }{
		{list: []string{"ps", "-a", "--filter", "label=" + labelManaged + "=1", "--format", listFormat}, rm: []string{"rm", "-f"}},
		{list: []string{"network", "ls", "--filter", "label=" + labelManaged + "=1", "--format", listFormat}, rm: []string{"network", "rm"}},
	}
	removed := 0
	var errs []error
	for _, k := range kinds {
		out, err := run(ctx, k.list...)
		if err != nil {
			return removed, err
		}
		for _, id := range stale(out, live, now) {
			if _, err := run(ctx, append(slices.Clone(k.rm), id)...); err != nil {
				errs = append(errs, err)
				continue
			}
			removed++
		}
	}
	return removed, errors.Join(errs...)
}

// stale picks from a listing (one object per line: id, session, created,
// tab separated) the ids Reap may remove: the session is not live and the
// object is at least reapMinAge old. A line it cannot read is kept; nothing
// is removed on a guess.
func stale(listing string, live func(string) bool, now time.Time) []string {
	var ids []string
	for _, line := range strings.Split(listing, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || f[0] == "" {
			continue
		}
		created, err := time.Parse(createdLayout, strings.TrimSpace(f[2]))
		if err != nil || now.Sub(created) < reapMinAge {
			continue
		}
		if live != nil && f[1] != "" && live(f[1]) {
			continue
		}
		ids = append(ids, f[0])
	}
	return ids
}
