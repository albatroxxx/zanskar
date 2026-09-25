// SPDX-License-Identifier: Apache-2.0

// Package server wires the HTTP router, middleware and system endpoints.
// Domain handlers register themselves on the router in later phases.
package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/version"
	"github.com/albatroxxx/zanskar/web"
)

// Server owns the listener and the router.
type Server struct {
	cfg  *config.Config
	db   *store.DB
	log  *slog.Logger
	http *http.Server
}

// Registrar is anything that mounts routes on the mux. Every domain handler
// package exposes one so the server never imports domain packages directly.
type Registrar interface {
	Register(mux *http.ServeMux)
}

// Deps are the domain handlers the server mounts. Nil fields are skipped,
// which keeps the system routes testable on their own.
type Deps struct {
	AuthMiddleware *auth.Middleware
	Auth           *auth.Handler
	Handlers       []Registrar
}

// New builds a Server with the system routes and the given handlers registered.
func New(cfg *config.Config, db *store.DB, log *slog.Logger, deps Deps) *Server {
	s := &Server{cfg: cfg, db: db, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /api/v1/version", s.handleVersion)
	mux.HandleFunc("/api/", s.handleNotFound)
	mux.HandleFunc("/ws/", s.handleNotFound)
	mux.Handle("/", spaHandler(web.FS()))
	if deps.Auth != nil {
		deps.Auth.Register(mux)
	}
	for _, h := range deps.Handlers {
		h.Register(mux)
	}

	// RealIP runs before accessLog and the handlers so the forwarded client
	// address, not the proxy's, reaches the log and every audit row.
	mws := []middleware{s.recoverer, requestID, auth.RealIP(cfg.TrustedProxies), s.securityHeaders, s.accessLog}
	if deps.AuthMiddleware != nil {
		mws = append(mws, deps.AuthMiddleware.Authenticate, deps.AuthMiddleware.CSRF)
	}

	s.http = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           chain(mux, mws...),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // WebSocket streams are long-lived; per-handler deadlines instead
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	return s
}

// ListenAndServe blocks until ctx is cancelled, then shuts down gracefully.
func (s *Server) ListenAndServe(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		var err error
		if s.cfg.TLSCert != "" {
			s.log.Info("listening", "addr", s.cfg.ListenAddr, "tls", true)
			err = s.http.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
		} else {
			s.log.Warn("listening without TLS; acceptable only behind a TLS-terminating proxy on loopback or a private container network", "addr", s.cfg.ListenAddr)
			err = s.http.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		return s.http.Shutdown(shutdownCtx)
	}
}

// ---- system handlers

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		s.log.Error("readiness: database ping failed", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "database unavailable"})
		return
	}
	pending, err := store.Pending(ctx, s.db)
	if err != nil || len(pending) > 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "migrations pending", "pending": pending})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": version.Version})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusNotFound, "not_found", "no such route")
}

// ---- response helpers

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	writeJSON(w, status, apiError{Code: code, Message: msg, RequestID: RequestIDFrom(r.Context())})
}

// ---- middleware

type middleware func(http.Handler) http.Handler

// chain applies middlewares so that the first listed is the outermost.
func chain(h http.Handler, mws ...middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

type ctxKey int

const ctxRequestID ctxKey = iota

// RequestIDFrom returns the request id set by the requestID middleware.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(ctxRequestID).(string)
	return id
}

// requestID assigns a fresh random id to every request. Client-supplied ids
// are ignored on purpose: they would let a caller forge log correlation.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b [8]byte
		_, _ = rand.Read(b[:])
		id := hex.EncodeToString(b[:])
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxRequestID, id)))
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if p := r.URL.Path; strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/ws/") || p == "/healthz" || p == "/readyz" {
			h.Set("Cache-Control", "no-store")
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		} else {
			h.Set("Content-Security-Policy", uiCSP)
		}
		if s.cfg.TLSCert != "" {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach Hijack and Flush on the real
// writer, which WebSocket upgrades need.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Hijack is kept for libraries that type-assert http.Hijacker directly.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		r.status = http.StatusSwitchingProtocols
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Flush passes through streaming flushes.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		// Query strings are intentionally not logged: connect tickets travel there.
		s.log.Info("http",
			"request_id", RequestIDFrom(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", auth.ClientIP(r),
		)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic", "request_id", RequestIDFrom(r.Context()), "panic", rec)
				writeError(w, r, http.StatusInternalServerError, "internal", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
