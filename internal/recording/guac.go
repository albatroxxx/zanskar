// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"context"
	"errors"
	"strings"
)

// ErrClosed is what a write to a recording that was closed answers. A bridge's
// last read can reach the recording just after the session's end closed it: that
// is the session ending, not a recording that failed (live, 2026-11-05: an
// error line for an RDP session that ended as user exit).
var ErrClosed = errors.New("recording: closed")

// GuacStream stores the server-to-client Guacamole instruction stream as
// guacd emitted it. guacamole-common-js's SessionRecording replays this
// format directly, and it is what guacd's own recording feature produces.
type GuacStream struct {
	sink
	frames int
}

// NewGuacStream starts a desktop recording on the storage under name.
func NewGuacStream(ctx context.Context, st Storage, name string) (*GuacStream, string, error) {
	wc, uri, err := st.Create(ctx, name)
	if err != nil {
		return nil, "", err
	}
	return &GuacStream{sink: newSink(wc, 64<<10)}, uri, nil
}

// Write appends one raw instruction. It implements guac.Recorder.
func (g *GuacStream) Write(raw string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return ErrClosed
	}
	if _, err := g.w.WriteString(raw); err != nil {
		return err
	}
	g.hash.Write([]byte(raw))
	g.size += int64(len(raw))
	g.frames += strings.Count(raw, syncOpcode)
	return nil
}

// syncOpcode opens guacd's sync instruction, which ends each frame it draws.
const syncOpcode = "4.sync,"

// Frames is how many frames the stream has carried. None is a session that
// never drew: guacd could not log on, say, and the desktop stayed blank
// (2026-11-03 live audit, Q6).
func (g *GuacStream) Frames() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.frames
}
