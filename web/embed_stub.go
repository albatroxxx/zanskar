// SPDX-License-Identifier: Apache-2.0

//go:build !webui

package web

import (
	"io/fs"
	"testing/fstest"
)

// Enabled reports whether a UI bundle is compiled in.
const Enabled = false

// FS returns a one-page placeholder when the binary was built without the
// webui tag, so the API still works and the operator sees why the UI is missing.
func FS() fs.FS {
	return fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte(`<!doctype html><meta charset="utf-8"><title>Zanskar</title>
<body style="font:15px system-ui;padding:40px;max-width:60ch"><h1>Zanskar</h1>
<p>This binary was built without the web UI. Build it with <code>make build</code>
(which runs <code>npm run build</code> in <code>web/</code> and compiles with <code>-tags webui</code>).
The API at <code>/api/v1</code> is available.</p></body>`)},
	}
}
