// SPDX-License-Identifier: Apache-2.0

// Package recording captures terminal sessions in asciicast v2 format and
// stores them through a Storage backend. Recordings are written as they
// happen so a crash mid-session still leaves a usable file up to that point.
package recording

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Storage persists recording blobs. URIs are opaque to callers.
type Storage interface {
	// Create opens a new blob for writing and returns its URI.
	Create(ctx context.Context, name string) (io.WriteCloser, string, error)
	// Open reads a blob back.
	Open(ctx context.Context, uri string) (io.ReadCloser, error)
	// Delete removes a blob. Removing one that is already gone is not an error,
	// so retention sweeps are idempotent.
	Delete(ctx context.Context, uri string) error
}

// LocalStorage keeps recordings under a directory. Files are created with
// mode 0600 inside a 0700 directory; the gateway process is the only reader.
type LocalStorage struct {
	Dir string
}

// Create implements Storage.
func (l *LocalStorage) Create(_ context.Context, name string) (io.WriteCloser, string, error) {
	if strings.ContainsAny(name, `/\`) || name == "" {
		return nil, "", errors.New("recording: bad name")
	}
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return nil, "", err
	}
	path := filepath.Join(l.Dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- name validated above, dir is ours
	if err != nil {
		return nil, "", err
	}
	return f, "file://" + path, nil
}

// Open implements Storage.
func (l *LocalStorage) Open(_ context.Context, uri string) (io.ReadCloser, error) {
	path := strings.TrimPrefix(uri, "file://")
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root, err := filepath.Abs(l.Dir)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(abs, root+string(filepath.Separator)) {
		return nil, errors.New("recording: uri outside storage directory")
	}
	return os.Open(abs) // #nosec G304 -- confined to the storage directory above
}

// Delete implements Storage. It confines removal to the storage directory and
// treats an already-absent file as success, so a retention sweep is idempotent.
func (l *LocalStorage) Delete(_ context.Context, uri string) error {
	path := strings.TrimPrefix(uri, "file://")
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	root, err := filepath.Abs(l.Dir)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(abs, root+string(filepath.Separator)) {
		return errors.New("recording: uri outside storage directory")
	}
	if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Header is the asciicast v2 header line.
type Header struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Title     string            `json:"title,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

// Asciicast writes an asciicast v2 stream: a JSON header then one JSON array
// per event: [elapsed_seconds, "o"|"i"|"r", data].
type Asciicast struct {
	mu     sync.Mutex
	w      *bufio.Writer
	closer io.Closer
	hash   hash.Hash
	size   int64
	start  time.Time
	closed bool
	// RecordInput captures keystrokes too. Off by default: input often
	// contains passwords typed into the remote shell.
	RecordInput bool
}

// NewAsciicast starts a recording on the storage under name.
func NewAsciicast(ctx context.Context, st Storage, name string, h Header) (*Asciicast, string, error) {
	wc, uri, err := st.Create(ctx, name)
	if err != nil {
		return nil, "", err
	}
	h.Version = 2
	if h.Timestamp == 0 {
		h.Timestamp = time.Now().Unix()
	}
	a := &Asciicast{w: bufio.NewWriterSize(wc, 32<<10), closer: wc, hash: sha256.New(), start: time.Now()}
	line, err := json.Marshal(h)
	if err != nil {
		_ = wc.Close()
		return nil, "", err
	}
	if err := a.writeLine(line); err != nil {
		_ = wc.Close()
		return nil, "", err
	}
	return a, uri, nil
}

// Output records bytes sent to the terminal.
func (a *Asciicast) Output(data []byte) error { return a.event("o", string(data)) }

// Input records bytes typed by the user, when enabled.
func (a *Asciicast) Input(data []byte) error {
	if !a.RecordInput {
		return nil
	}
	return a.event("i", string(data))
}

// Resize records a terminal size change.
func (a *Asciicast) Resize(cols, rows int) error {
	return a.event("r", fmt.Sprintf("%dx%d", cols, rows))
}

// Marker records an annotation, such as a failover.
func (a *Asciicast) Marker(label string) error { return a.event("m", label) }

func (a *Asciicast) event(kind, data string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return errors.New("recording: closed")
	}
	elapsed := time.Since(a.start).Seconds()
	line, err := json.Marshal([]any{elapsed, kind, data})
	if err != nil {
		return err
	}
	return a.writeLine(line)
}

func (a *Asciicast) writeLine(line []byte) error {
	if _, err := a.w.Write(line); err != nil {
		return err
	}
	if err := a.w.WriteByte('\n'); err != nil {
		return err
	}
	a.hash.Write(line)
	a.hash.Write([]byte{'\n'})
	a.size += int64(len(line)) + 1
	return nil
}

// Flush pushes buffered events to storage without closing.
func (a *Asciicast) Flush() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.w.Flush()
}

// Close finishes the recording and returns its size and SHA-256.
func (a *Asciicast) Close() (int64, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return a.size, hex.EncodeToString(a.hash.Sum(nil)), nil
	}
	a.closed = true
	if err := a.w.Flush(); err != nil {
		_ = a.closer.Close()
		return 0, "", err
	}
	if err := a.closer.Close(); err != nil {
		return 0, "", err
	}
	return a.size, hex.EncodeToString(a.hash.Sum(nil)), nil
}
