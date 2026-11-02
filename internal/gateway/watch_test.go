// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Four eyes (ADR 0042): a held session goes on when someone other than its
// owner watches it; the owner watching themself counts for nothing; nobody
// in time is ErrNoWatcher; a terminate ends the wait with its cause.
func TestAwaitWatcher(t *testing.T) {
	r := NewRegistry()
	ctx := r.Add(context.Background(), Live{SessionID: "s1", UserID: "alice", Protocol: "ssh"})

	if err := r.AwaitWatcher(ctx, "s1", 30*time.Millisecond); !errors.Is(err, ErrNoWatcher) {
		t.Fatalf("nobody: %v", err)
	}
	r.Watch("s1", "alice", +1)
	if r.Watched("s1") {
		t.Fatal("the owner watching themself counted")
	}
	done := make(chan error, 1)
	go func() { done <- r.AwaitWatcher(ctx, "s1", 5*time.Second) }()
	time.Sleep(20 * time.Millisecond)
	r.Watch("s1", "bob", +1)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a watcher came: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a watcher did not release the session")
	}
	// Once released, a later wait returns at once; watchers leaving is counted.
	if err := r.AwaitWatcher(ctx, "s1", time.Millisecond); err != nil {
		t.Fatalf("after release: %v", err)
	}
	r.Watch("s1", "bob", -1)
	if r.Watched("s1") {
		t.Fatal("bob left, still watched")
	}

	ctx2 := r.Add(context.Background(), Live{SessionID: "s2", UserID: "alice", Protocol: "ssh"})
	go func() { time.Sleep(20 * time.Millisecond); r.TerminateWithCause("s2", ErrAdminTerminated) }()
	if err := r.AwaitWatcher(ctx2, "s2", 5*time.Second); !errors.Is(err, ErrAdminTerminated) {
		t.Fatalf("terminated while waiting: %v", err)
	}
	if err := r.AwaitWatcher(context.Background(), "gone", time.Millisecond); err == nil {
		t.Fatal("a session that is not live was awaited")
	}
}
