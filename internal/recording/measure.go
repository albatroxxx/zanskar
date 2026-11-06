// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// Measure reads a stored recording and returns its size and SHA-256, what a
// recording's own Close returns as it is written: for one whose close never
// ran, the gateway gone or the write that finished it failed, so its row can be
// finished from what storage holds.
func Measure(ctx context.Context, st Storage, uri string) (size int64, digest string, err error) {
	rc, err := st.Open(ctx, uri)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = rc.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, rc)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}
