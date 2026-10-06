// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// maxResponse bounds what one inner API call may return to the command line.
const maxResponse = 4 << 20

// apiCall is one request a command made, kept for the audit event.
type apiCall struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}

// apiError is an API error reply, kept whole so a command can say why.
type apiError struct {
	Status  int
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *apiError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return http.StatusText(e.Status)
}

// caller sends a command's requests through the router itself, with the
// context of the console request that carried the line. The route's own
// guards (RequireRole and the rest) therefore see the same principal, client
// address and request id as any console click: the command line can do
// exactly what the API lets this user do (ADR 0027).
type caller struct {
	mux        http.Handler
	ctx        context.Context
	remoteAddr string
	calls      []apiCall
}

// get decodes a GET of path (under /api/v1) into out.
func (c *caller) get(path string, out any) error { return c.do(http.MethodGet, path, nil, out) }

func (c *caller) do(method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(c.ctx, method, "/api/v1"+path, rdr)
	if err != nil {
		return err
	}
	req.RemoteAddr = c.remoteAddr
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := &recorder{header: http.Header{}}
	c.mux.ServeHTTP(rec, req)
	status := rec.statusCode()
	c.calls = append(c.calls, apiCall{Method: method, Path: req.URL.Path, Status: status})
	if rec.overflow {
		return fmt.Errorf("the reply from %s was too large to show", req.URL.Path)
	}
	if status >= 400 {
		e := &apiError{Status: status}
		_ = json.Unmarshal(rec.body.Bytes(), e)
		return e
	}
	if out == nil || rec.body.Len() == 0 {
		return nil
	}
	return json.Unmarshal(rec.body.Bytes(), out)
}

// pathf builds an API path, escaping each argument as one path segment.
// Arguments have already passed checkName; escaping is the second guard.
func pathf(format string, args ...string) string {
	esc := make([]any, len(args))
	for i, a := range args {
		esc[i] = url.PathEscape(a)
	}
	return fmt.Sprintf(format, esc...)
}

// recorder is a minimal http.ResponseWriter that keeps the reply in memory.
type recorder struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}

func (r *recorder) Write(p []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	if r.body.Len()+len(p) > maxResponse {
		r.overflow = true
		return len(p), nil
	}
	return r.body.Write(p)
}

func (r *recorder) statusCode() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}
