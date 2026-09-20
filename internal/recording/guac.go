// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"sync"
)

// GuacStream stores the server-to-client Guacamole instruction stream as
// guacd emitted it. guacamole-common-js's SessionRecording replays this
// format directly, and it is what guacd's own recording feature produces.
type GuacStream struct {
	mu     sync.Mutex
	w      *bufio.Writer
	closer io.Closer
	hash   hash.Hash
	size   int64
	closed bool
}

// NewGuacStream starts a desktop recording on the storage under name.
func NewGuacStream(ctx context.Context, st Storage, name string) (*GuacStream, string, error) {
	wc, uri, err := st.Create(ctx, name)
	if err != nil {
		return nil, "", err
	}
	return &GuacStream{w: bufio.NewWriterSize(wc, 64<<10), closer: wc, hash: sha256.New()}, uri, nil
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

// Close finishes the recording and returns its size and SHA-256.
func (g *GuacStream) Close() (int64, string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return g.size, hex.EncodeToString(g.hash.Sum(nil)), nil
	}
	g.closed = true
	if err := g.w.Flush(); err != nil {
		_ = g.closer.Close()
		return 0, "", err
	}
	if err := g.closer.Close(); err != nil {
		return 0, "", err
	}
	return g.size, hex.EncodeToString(g.hash.Sum(nil)), nil
}
