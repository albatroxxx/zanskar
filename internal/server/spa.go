// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// spaHandler serves the embedded single-page app. Hashed assets under
// /assets/ are cacheable; every other path falls back to index.html so
// client-side routes deep-link. API and WebSocket paths never reach here.
func spaHandler(bundle fs.FS) http.Handler {
	files := http.FS(bundle)
	fileServer := http.FileServer(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := path.Clean("/" + r.URL.Path)
		if p != "/" {
			if f, err := bundle.Open(strings.TrimPrefix(p, "/")); err == nil {
				_ = f.Close()
				if strings.HasPrefix(p, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		// SPA fallback.
		w.Header().Set("Cache-Control", "no-store")
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, r2)
	})
}

// uiCSP is the policy for HTML and bundle responses. Scripts and styles come
// only from our own origin; xterm and the recording player inject inline
// styles, so style-src allows them. Connections are limited to our origin
// (API) and its WebSocket.
const uiCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' ws: wss:; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
