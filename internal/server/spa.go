// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// consoleRoots are the first path segments the console has pages under; ""
// is the access portal's own root. A path under one of them gets index.html,
// so a page deep-links; any other path that is not a bundle file is not
// found. Before 1.15.0 every path answered 200 with the app, /.git/HEAD and
// /metrics too, and every scanner reported them exposed (2026-11-03 live
// audit, S1). Keep in step with web/src/App.tsx.
var consoleRoots = map[string]bool{
	"": true, "login": true, "home": true, "connect": true, "access": true, "sessions": true,
	"activity": true, "terminal": true, "desktop": true, "admin": true, "audit": true,
}

// isConsolePath reports whether p, already cleaned, is a page of the console.
func isConsolePath(p string) bool {
	first, _, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	return consoleRoots[first]
}

// robotsTxt keeps search engines out of the whole gateway: it is a door,
// not a site.
const robotsTxt = "User-agent: *\nDisallow: /\n"

// spaHandler serves the embedded single-page app. Hashed assets under
// /assets/ are cacheable; a console page falls back to index.html so
// client-side routes deep-link, and anything else is not found. API and
// WebSocket paths never reach here.
func spaHandler(bundle fs.FS) http.Handler {
	files := http.FS(bundle)
	fileServer := http.FileServer(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := path.Clean("/" + r.URL.Path)
		// A directory is not a page: it gets the app like any unknown path,
		// never a listing of the bundle (L8).
		if p != "/" && isFile(bundle, strings.TrimPrefix(p, "/")) {
			markStatic(r)
			if strings.HasPrefix(p, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			fileServer.ServeHTTP(w, r)
			return
		}
		if p == "/robots.txt" {
			markStatic(r)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, robotsTxt)
			return
		}
		if !isConsolePath(p) {
			w.Header().Set("Cache-Control", "no-store")
			http.NotFound(w, r)
			return
		}
		// SPA fallback.
		w.Header().Set("Cache-Control", "no-store")
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, r2)
	})
}

// isFile reports whether name is a regular file in the bundle.
func isFile(bundle fs.FS, name string) bool {
	st, err := fs.Stat(bundle, name)
	return err == nil && st.Mode().IsRegular()
}

// uiCSP is the policy for HTML and bundle responses. Scripts and styles come
// only from our own origin; xterm and the recording player inject inline
// styles, so style-src allows them: xterm's renderer writes each cell's
// colours as a style attribute and sizes its viewport with a <style>
// element, and terminals open in tabs of their own that a route-scoped
// policy would not follow (re-checked for the 2026-11-03 live audit, S3). 'wasm-unsafe-eval' lets the asciicast
// player instantiate its WebAssembly terminal emulator; without it recording
// playback is a blank screen. It permits WebAssembly only, not JavaScript
// eval, so script injection protection is unchanged. Connections stay on our
// origin: 'self' covers its WebSocket too in every browser the bundle is
// built for (L5).
const uiCSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
