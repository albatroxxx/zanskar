// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"testing"
)

func TestTapReplayAndFanOut(t *testing.T) {
	tp := NewTap()
	tp.Write([]byte("hello "))
	ch, replay, cancel := tp.Subscribe()
	defer cancel()
	if string(replay) != "hello " {
		t.Fatalf("replay %q", replay)
	}
	tp.Write([]byte("world"))
	if got := <-ch; string(got) != "world" {
		t.Fatalf("live %q", got)
	}
	if tp.Watchers() != 1 {
		t.Fatal("expected one watcher")
	}
	cancel()
	if tp.Watchers() != 0 {
		t.Fatal("cancel must unsubscribe")
	}
	if _, ok := <-ch; ok {
		t.Fatal("channel must be closed after cancel")
	}
}

func TestTapRingLimitAndDrops(t *testing.T) {
	tp := NewTap()
	big := bytes.Repeat([]byte("x"), replayBytes+100)
	tp.Write(big)
	tp.Write([]byte("tail"))
	_, replay, cancel := tp.Subscribe()
	defer cancel()
	if len(replay) != replayBytes || !bytes.HasSuffix(replay, []byte("tail")) {
		t.Fatalf("ring size %d, suffix %q", len(replay), replay[len(replay)-4:])
	}
	// A slow subscriber never blocks the writer.
	for i := 0; i < 300; i++ {
		tp.Write([]byte("c"))
	}
	if tp.Dropped.Load() == 0 {
		t.Fatal("expected drops for a slow subscriber")
	}
	tp.Close()
	ch, _, _ := tp.Subscribe()
	if _, ok := <-ch; ok {
		t.Fatal("subscribe after close must yield a closed channel")
	}
	tp.Write([]byte("ignored"))
}

func TestRegistryTapLifecycle(t *testing.T) {
	r := NewRegistry()
	ctx := r.Add(context.Background(), Live{SessionID: "s1", UserID: "u1", Protocol: "ssh"})
	if r.Tap("s1") == nil {
		t.Fatal("ssh session must get a tap")
	}
	r.Add(context.Background(), Live{SessionID: "d1", UserID: "u1", Protocol: "rdp"})
	if r.Tap("d1") != nil {
		t.Fatal("desktop session must not get a tap")
	}
	r.SetGuacID("d1", "$abc")
	if l, ok := r.Get("d1"); !ok || l.GuacID != "$abc" {
		t.Fatalf("guac id not recorded: %+v %v", l, ok)
	}
	ch, _, cancel := r.Tap("s1").Subscribe()
	defer cancel()
	r.Remove("s1")
	if _, ok := <-ch; ok {
		t.Fatal("removing the session must close watcher channels")
	}
	if ctx.Err() != nil {
		t.Fatal("remove must not cancel the bridge context")
	}
	if _, ok := r.Get("s1"); ok {
		t.Fatal("removed session still listed")
	}
}
