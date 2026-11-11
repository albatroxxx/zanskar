// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/recording"
)

// heldCloseStorage keeps recordings on disk but holds every Close until the
// test lets it go, as an upload to a slow bucket would, and says when a Close
// began.
type heldCloseStorage struct {
	*recording.LocalStorage
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type heldCloser struct {
	io.WriteCloser
	s *heldCloseStorage
}

func (c heldCloser) Close() error {
	c.s.once.Do(func() { close(c.s.entered) })
	<-c.s.release
	return c.WriteCloser.Close()
}

func (s *heldCloseStorage) Create(ctx context.Context, name string) (io.WriteCloser, string, error) {
	w, uri, err := s.LocalStorage.Create(ctx, name)
	return heldCloser{w, s}, uri, err
}

// TestFileTransferEndsWithTheBridge (ADR 0047, 2026-11-09): the SSH client a
// session's file endpoints use was dropped from the registry only when the
// terminal handler returned, after the recording was closed and uploaded. A
// session that revocation or a changed host key ended kept listing,
// downloading and uploading files for as long as that took. The client
// leaves the registry when the bridge ends.
func TestFileTransferEndsWithTheBridge(t *testing.T) {
	port, fp := shellTarget(t)
	r := newTerminalRig(t, port, fp)
	storage := &heldCloseStorage{LocalStorage: &recording.LocalStorage{Dir: t.TempDir()}, entered: make(chan struct{}), release: make(chan struct{})}
	r.h.Storage = storage
	// Let the fixture's policy allow file transfer, so the session is in
	// the registry at all.
	p, err := r.h.Policies.Get(r.ctx, r.policyIDs["test-all"])
	if err != nil {
		t.Fatal(err)
	}
	hostGrant(p).AllowFileTransfer = true
	if err := r.h.Policies.Update(r.ctx, p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id := r.liveShell(t, ctx)
	if _, ok := r.h.Files.lookup(id, r.alice.ID); !ok {
		t.Fatal("a live session with file transfer allowed must be in the file registry")
	}
	if n := r.h.Registry.Terminate(id); !n {
		t.Fatal("terminate: session not live")
	}
	// The bridge has ended and the recording's close is being held, as a
	// slow upload would hold it: the session is closing, not live.
	select {
	case <-storage.entered:
	case <-ctx.Done():
		t.Fatal("the recording's close never began")
	}
	if _, ok := r.h.Files.lookup(id, r.alice.ID); ok {
		t.Fatal("the session's SSH client still serves file transfer while its recording is being closed")
	}
	close(storage.release)
	var ended bool
	for i := 0; i < 200 && !ended; i++ {
		s, err := r.h.Sessions.Get(r.ctx, id)
		ended = err == nil && s.EndedAt != nil
		if !ended {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !ended {
		t.Fatal("session not ended")
	}
}
