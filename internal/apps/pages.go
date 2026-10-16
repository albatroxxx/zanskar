// SPDX-License-Identifier: Apache-2.0

package apps

import (
	"html/template"
	"net/http"

	"github.com/albatroxxx/zanskar/internal/httpx"
)

// pageTmpl is the one page the proxy shows of its own: a title, a sentence
// and, when there is one, the way back to the console. Plain HTML with no
// script, under a policy that allows nothing else.
var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · Zanskar</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f6f3ee;color:#2b2724;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:28rem;padding:2rem;background:#fffdf9;border:1px solid #e4ddd2;border-radius:12px;box-shadow:0 1px 2px rgba(43,39,36,.06)}
h1{margin:0 0 .5rem;font-size:1.25rem}p{margin:0 0 1rem}
a{color:#2244aa;text-decoration:none;font-weight:600}a:hover{text-decoration:underline}
</style></head>
<body><main><h1>{{.Title}}</h1><p>{{.Body}}</p>{{if .Console}}<p><a href="{{.Console}}">Back to Zanskar</a></p>{{end}}</main></body></html>
`))

// page answers a request on an application host with the proxy's own words.
func (h *Handler) page(w http.ResponseWriter, status int, title, body string, console bool) {
	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	link := ""
	if console {
		link = h.PublicURL
	}
	_ = pageTmpl.Execute(w, map[string]string{"Title": title, "Body": body, "Console": link})
}

// requestID is the request id for a log line.
func requestID(r *http.Request) string { return httpx.RequestID(r.Context()) }
