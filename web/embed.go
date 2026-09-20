// SPDX-License-Identifier: Apache-2.0

//go:build webui

// Package web embeds the built single-page application. Build the bundle
// with `make web` (or `npm run build` in web/) and compile with -tags webui.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Enabled reports whether a UI bundle is compiled in.
const Enabled = true

// FS returns the bundle rooted at dist/.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
