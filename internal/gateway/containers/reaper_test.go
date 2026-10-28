// SPDX-License-Identifier: Apache-2.0

package containers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeDocker scripts the listings a reaper sees and records what it removes.
type fakeDocker struct {
	containers, networks string
	failRemove           map[string]bool
	calls                [][]string
}

func (f *fakeDocker) run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, args)
	switch {
	case args[0] == "ps":
		return f.containers, nil
	case args[0] == "network" && args[1] == "ls":
		return f.networks, nil
	case args[0] == "rm" || (args[0] == "network" && args[1] == "rm"):
		if f.failRemove[args[len(args)-1]] {
			return "", fmt.Errorf("docker %s: no such object", args[0])
		}
		return "", nil
	}
	return "", fmt.Errorf("unexpected docker %v", args)
}

// TestReapRemovesOnlyStaleObjectsOfDeadSessions: an object goes when its
// session is not live and it is at least two minutes old; a live session's
// objects, a start still in flight, and a line that cannot be read all stay.
// Containers are removed before networks, and only labelled objects are
// listed at all.
func TestReapRemovesOnlyStaleObjectsOfDeadSessions(t *testing.T) {
	now := time.Date(2026, 10, 11, 10, 0, 0, 0, time.FixedZone("IST", 5*3600+1800))
	at := func(age time.Duration) string { return now.Add(-age).Format(createdLayout) }
	fd := &fakeDocker{
		containers: strings.Join([]string{
			"c-live-old\tlive\t" + at(10*time.Minute),
			"c-dead-young\tdead\t" + at(90*time.Second),
			"c-dead-old\tdead\t" + at(3*time.Minute),
			"c-nolabel-old\t\t" + at(time.Hour),
			"c-unreadable\tdead\tyesterday",
			"",
		}, "\n"),
		// network ls prints fractional seconds; ps does not.
		networks: "n-dead-old\tdead\t" + now.Add(-time.Hour).Format("2006-01-02 15:04:05.000000000 -0700 MST") + "\n" +
			"n-live-old\tlive\t" + at(time.Hour) + "\n",
	}
	live := func(id string) bool { return id == "live" }
	n, err := ReapWith(context.Background(), fd.run, live, now)
	if err != nil || n != 3 {
		t.Fatalf("reap removed %d, err %v", n, err)
	}
	const format = `{{.ID}}\t{{.Label "zanskar.session"}}\t{{.CreatedAt}}`
	want := [][]string{
		{"ps", "-a", "--filter", "label=zanskar.managed=1", "--format", format},
		{"rm", "-f", "c-dead-old"},
		{"rm", "-f", "c-nolabel-old"},
		{"network", "ls", "--filter", "label=zanskar.managed=1", "--format", format},
		{"network", "rm", "n-dead-old"},
	}
	if !reflect.DeepEqual(fd.calls, want) {
		t.Fatalf("docker calls:\n got %q\nwant %q", fd.calls, want)
	}
}

// TestReapKeepsGoingPastARemovalFailure: one object that will not go does
// not stop the others; a listing that fails ends the pass with nothing
// removed, since there is nothing trustworthy to act on.
func TestReapKeepsGoingPastARemovalFailure(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour).Format(createdLayout)
	fd := &fakeDocker{containers: "c1\ts1\t" + old + "\nc2\ts2\t" + old + "\n", networks: "n1\ts1\t" + old + "\n",
		failRemove: map[string]bool{"c1": true}}
	n, err := ReapWith(context.Background(), fd.run, nil, now)
	if n != 2 || err == nil || !strings.Contains(err.Error(), "no such object") {
		t.Fatalf("removed %d, err %v", n, err)
	}
	if last := fd.calls[len(fd.calls)-1]; !reflect.DeepEqual(last, []string{"network", "rm", "n1"}) {
		t.Fatalf("the network was not removed after the failed container: %q", fd.calls)
	}
	down := func(_ context.Context, _ ...string) (string, error) {
		return "", errors.New("cannot connect to the docker daemon")
	}
	if n, err := ReapWith(context.Background(), down, nil, now); n != 0 || err == nil {
		t.Fatalf("a failed listing removed %d, err %v", n, err)
	}
}

// TestReapReadsBothCreatedAtShapes pins the layout to what this Docker
// prints for a container and for a network, so a drift in either is a test
// failure rather than objects silently never reaped.
func TestReapReadsBothCreatedAtShapes(t *testing.T) {
	for _, s := range []string{"2026-10-11 15:03:56 +0530 IST", "2026-10-11 15:03:56.920849998 +0530 IST"} {
		ts, err := time.Parse(createdLayout, s)
		if err != nil || ts.UTC().Format(time.RFC3339) != "2026-10-11T09:33:56Z" {
			t.Errorf("%q parsed as %v, %v", s, ts, err)
		}
	}
	if listFormat != `{{.ID}}\t{{.Label "zanskar.session"}}\t{{.CreatedAt}}` {
		t.Errorf("list format changed: %s", listFormat)
	}
}
