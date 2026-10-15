// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"bufio"
	"net"
	"net/http"
)

// StatusRecorder notes the status and the bytes a handler writes, for the
// access logs. It passes Hijack and Flush through, which WebSocket upgrades
// and streaming responses need, and Unwrap lets http.ResponseController
// reach them on the real writer.
type StatusRecorder struct {
	http.ResponseWriter
	Status int
	Bytes  int64
}

// NewStatusRecorder wraps w; the status reads 200 until WriteHeader says otherwise.
func NewStatusRecorder(w http.ResponseWriter) *StatusRecorder {
	return &StatusRecorder{ResponseWriter: w, Status: http.StatusOK}
}

// WriteHeader records the status.
func (r *StatusRecorder) WriteHeader(code int) {
	r.Status = code
	r.ResponseWriter.WriteHeader(code)
}

// Write counts the body.
func (r *StatusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.Bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach Hijack and Flush on the real writer.
func (r *StatusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Hijack is kept for libraries that type-assert http.Hijacker directly; a
// hijacked connection was upgraded.
func (r *StatusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		r.Status = http.StatusSwitchingProtocols
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Flush passes through streaming flushes.
func (r *StatusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
