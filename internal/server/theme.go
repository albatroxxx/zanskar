// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"io/fs"
	"net/http"
)

// themeMarker is the console theme's literal in web/public/theme.js; the
// gateway writes the theme an administrator set for everyone over it.
const themeMarker = `'system' /* zanskar:theme */`

// themeScript serves the console's pre-paint theme script with the theme set
// for everyone (display.theme) written in (2026-11-01), so every page, the
// sign-in page too, opens in it without a flash of the other. The bundle's
// file is the template, and the value written is one of three literals,
// never the stored text. Nil when the bundle has no theme script.
func themeScript(bundle fs.FS, theme func() string) http.Handler {
	src, err := fs.ReadFile(bundle, "theme.js")
	if err != nil {
		return nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		lit := `'system'`
		switch theme() {
		case "light":
			lit = `'light'`
		case "dark":
			lit = `'dark'`
		}
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		// A change in Settings applies at the next page load, everywhere.
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(bytes.Replace(src, []byte(themeMarker), []byte(lit+` /* zanskar:theme */`), 1))
	})
}
