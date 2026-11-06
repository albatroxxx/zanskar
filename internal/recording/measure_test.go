// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"context"
	"path/filepath"
	"testing"
)

// TestMeasureMatchesTheRecordingsOwnClose: what Measure reads back from storage
// is what the recording's Close reported as it was written, so a row finished
// by the sweep verifies as one finished by its bridge. A blob that is not there
// is an error, not an empty recording.
func TestMeasureMatchesTheRecordingsOwnClose(t *testing.T) {
	ctx := context.Background()
	st := &LocalStorage{Dir: t.TempDir()}
	a, uri, err := NewAsciicast(ctx, st, "m.cast", Header{Width: 80, Height: 24})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Output([]byte("hello\r\n")); err != nil {
		t.Fatal(err)
	}
	size, sum, err := a.Close()
	if err != nil {
		t.Fatal(err)
	}
	gotSize, gotSum, err := Measure(ctx, st, uri)
	if err != nil {
		t.Fatal(err)
	}
	if gotSize != size || gotSum != sum {
		t.Fatalf("measured %d %s, the close said %d %s", gotSize, gotSum, size, sum)
	}
	if _, _, err := Measure(ctx, st, "file://"+filepath.Join(st.Dir, "gone.cast")); err == nil {
		t.Fatal("a blob that is not there measured without error")
	}
}
