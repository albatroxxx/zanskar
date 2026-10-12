// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"context"
	"errors"
)

// GuacStream stores the server-to-client Guacamole instruction stream as
// guacd emitted it. guacamole-common-js's SessionRecording replays this
// format directly, and it is what guacd's own recording feature produces.
type GuacStream struct {
	sink
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
		return errors.New("recording: closed")
	}
	if _, err := g.w.WriteString(raw); err != nil {
		return err
	}
	g.hash.Write([]byte(raw))
	g.size += int64(len(raw))
	return nil
}
