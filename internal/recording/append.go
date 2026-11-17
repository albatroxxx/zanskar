// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Appender is a Storage that can add to a blob after its writer closed. The
// local directory can; an object store, which takes the blob whole when the
// writer closes, cannot, and a recording whose writer never closed is not
// there to add to.
type Appender interface {
	Append(ctx context.Context, uri string) (io.WriteCloser, error)
}

// ErrNoAppend: the storage cannot add to a stored recording.
var ErrNoAppend = errors.New("recording: this storage cannot append to a recording")

// AppendMarker adds one line to a stored asciicast after its writer is gone:
// a marker and an output event carrying label, timed from the header's
// timestamp as the writer would have timed them. The sweep uses it to say
// why a cloud session's activity was not read (ADR 0050, phase C) when the
// gateway that held the recording open restarted before its last read.
func AppendMarker(ctx context.Context, st Storage, uri, label string) error {
	ap, ok := st.(Appender)
	if !ok {
		return ErrNoAppend
	}
	started, err := headerTime(ctx, st, uri)
	if err != nil {
		return err
	}
	elapsed := 0.0
	if !started.IsZero() {
		elapsed = time.Since(started).Seconds()
	}
	w, err := ap.Append(ctx, uri)
	if err != nil {
		return err
	}
	for _, ev := range [][]any{{elapsed, "m", label}, {elapsed, "o", label + "\r\n"}} {
		line, err := json.Marshal(ev)
		if err != nil {
			_ = w.Close()
			return err
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			_ = w.Close()
			return err
		}
	}
	return w.Close()
}

// headerTime reads an asciicast's header line for when it started; the zero
// time when the header carries none.
func headerTime(ctx context.Context, st Storage, uri string) (time.Time, error) {
	rc, err := st.Open(ctx, uri)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = rc.Close() }()
	first, err := bufio.NewReader(io.LimitReader(rc, 1<<16)).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return time.Time{}, err
	}
	var h Header
	if err := json.Unmarshal(first, &h); err != nil || h.Version != 2 {
		return time.Time{}, fmt.Errorf("recording: not an asciicast header: %w", err)
	}
	if h.Timestamp == 0 {
		return time.Time{}, nil
	}
	return time.Unix(h.Timestamp, 0), nil
}
