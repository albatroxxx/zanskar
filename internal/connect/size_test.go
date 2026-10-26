// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"net/http/httptest"
	"testing"
)

// TestSizesAreBounded: the browser's terminal and screen sizes are taken
// inside the bridges' bounds, so the recording header, the bridge and guacd
// agree, and a probe cannot write a 2e9-column header that the auditor's
// player then tries to lay out (review finding SEC-8).
func TestSizesAreBounded(t *testing.T) {
	for _, tc := range []struct {
		query      string
		cols, rows int
	}{
		{"cols=100&rows=30", 100, 30},
		{"cols=1000&rows=500", 1000, 500},
		{"cols=1001&rows=501", 80, 24},
		{"cols=2000000000&rows=2000000000", 80, 24},
		{"cols=-5&rows=0", 80, 24},
		{"cols=abc&rows=", 80, 24},
		{"", 80, 24},
	} {
		r := httptest.NewRequest("GET", "/ws/terminal?"+tc.query, nil)
		if cols, rows := termSize(r); cols != tc.cols || rows != tc.rows {
			t.Errorf("%q: %dx%d, want %dx%d", tc.query, cols, rows, tc.cols, tc.rows)
		}
	}
	for _, tc := range []struct {
		query              string
		width, height, dpi int
	}{
		{"width=1024&height=768&dpi=96", 1024, 768, 96},
		{"width=8192&height=8192&dpi=480", 8192, 8192, 480},
		{"width=8193&height=-1&dpi=481", 0, 0, 0},
		{"width=2000000000&height=2000000000", 0, 0, 0},
		{"", 0, 0, 0},
	} {
		r := httptest.NewRequest("GET", "/ws/desktop?"+tc.query, nil)
		if w, h, d := screenSize(r); w != tc.width || h != tc.height || d != tc.dpi {
			t.Errorf("%q: %dx%d@%d, want %dx%d@%d", tc.query, w, h, d, tc.width, tc.height, tc.dpi)
		}
	}
}
