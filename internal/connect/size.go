// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"net/http"
	"strconv"
)

// Bounds on what the browser may ask for. The terminal ones are the bridges'
// own (sshgw, dbgw); the desktop ones are generous for any real display. A
// value outside them is the browser's mistake or a probe, and the recording
// header, the bridge and guacd must agree on what was used.
const (
	maxCols   = 1000
	maxRows   = 500
	maxPixels = 8192
	maxDPI    = 480
)

// termSize reads cols and rows from the query, bounded to the bridges'
// range; anything else becomes the bridges' default of 80 by 24, so the
// recording header says what the terminal was.
func termSize(r *http.Request) (cols, rows int) {
	cols, _ = strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ = strconv.Atoi(r.URL.Query().Get("rows"))
	if cols <= 0 || cols > maxCols {
		cols = 80
	}
	if rows <= 0 || rows > maxRows {
		rows = 24
	}
	return cols, rows
}

// screenSize reads width, height and dpi from the query, bounded; zero
// means "not given" and leaves guacd's default in place.
func screenSize(r *http.Request) (width, height, dpi int) {
	bound := func(name string, most int) int {
		v, _ := strconv.Atoi(r.URL.Query().Get(name))
		if v < 0 || v > most {
			return 0
		}
		return v
	}
	return bound("width", maxPixels), bound("height", maxPixels), bound("dpi", maxDPI)
}
