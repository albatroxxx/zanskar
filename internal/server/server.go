// SPDX-License-Identifier: Apache-2.0

// Package server wires the HTTP router, middleware and system endpoints.
// Domain handlers add their routes through Deps.
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/tlscert"
	"github.com/albatroxxx/zanskar/internal/version"
	"github.com/albatroxxx/zanskar/web"
)

// Server owns the listener and the router.
type Server struct {
	cfg      *config.Config
	db       *store.DB
	log      *slog.Logger
	http     *http.Server
	redirect *http.Server // plain HTTP to HTTPS, when configured
}

// Registrar is anything that mounts routes on the mux. Every domain handler
// package exposes one so the server never imports domain packages directly.
type Registrar interface {
	Register(mux *http.ServeMux)
}

// AppHost is the listener's second personality, served by host (ADR 0033):
// the applications proxy. Its traffic never passes the console's
// middlewares, since the console's cookie, CSRF rule and security headers
// are not for an application's pages; it gets the ones every request gets.
type AppHost interface {
	http.Handler
	// Serves reports whether a request's Host header names an application.
	Serves(host string) bool
}

// Deps are the domain handlers the server mounts. Nil fields are skipped,
// which keeps the system routes testable on their own.
type Deps struct {
	AuthMiddleware *auth.Middleware
	Auth           *auth.Handler
	Handlers       []Registrar
	// TLS hands the listener its certificate per handshake (ADR 0021): an
	// upload in the console, the ZANSKAR_TLS_CERT files, or the self-signed
	// one, so an upload applies without a restart. Nil in proxy mode.
	TLS *tlscert.Manager
	// Apps serves the application hosts; nil serves none.
	Apps AppHost
}

// New builds a Server with the system routes and the given handlers registered.
func New(cfg *config.Config, db *store.DB, log *slog.Logger, deps Deps) *Server {
	s := &Server{cfg: cfg, db: db, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	// The release is for people signed in (the console's command line asks
	// for it); told to anyone, it is what a scanner matches advisories by.
	mux.Handle("GET /api/v1/version", auth.RequireAuth(http.HandlerFunc(s.handleVersion)))
	mux.HandleFunc("/api/", s.handleNotFound)
	mux.HandleFunc("/ws/", s.handleNotFound)
	mux.Handle("/", spaHandler(web.FS()))
	if deps.Auth != nil {
		deps.Auth.Register(mux)
	}
	for _, h := range deps.Handlers {
		h.Register(mux)
	}

	// The request id comes first, so even a recovered panic answers and logs
	// with it. RealIP runs before accessLog and the handlers so the forwarded
	// client address, not the proxy's, reaches the log and every audit row.
	// Those three are for every request; the rest are the console's, and an
	// application host is dispatched past them.
	console := []middleware{s.securityHeaders, s.accessLog}
	if deps.AuthMiddleware != nil {
		console = append(console, deps.AuthMiddleware.Authenticate, deps.AuthMiddleware.CSRF)
	}
	root := chain(mux, console...)
	if deps.Apps != nil {
		root = dispatch(deps.Apps, root)
	}

	s.http = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           chain(root, requestID, s.recoverer, auth.RealIP(cfg.TrustedProxies)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // WebSocket streams are long-lived; per-handler deadlines instead
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	if cfg.ServesTLS() && deps.TLS != nil {
		s.http.TLSConfig = &tls.Config{GetCertificate: deps.TLS.GetCertificate, MinVersion: tls.VersionTLS12}
	}
	if cfg.ServesTLS() && cfg.RedirectAddr != "" {
		var covered func() []string
		if deps.TLS != nil {
			covered = func() []string { return slices.Concat(deps.TLS.Active().Hosts, deps.TLS.AppsHosts()) }
		}
		s.redirect = newRedirectServer(cfg.RedirectAddr, cfg.ListenAddr, covered)
	}
	return s
}

// dispatch sends a request to the application host its Host header names,
// else to the console.
func dispatch(apps AppHost, console http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apps.Serves(r.Host) {
			apps.ServeHTTP(w, r)
			return
		}
		console.ServeHTTP(w, r)
	})
}

// ListenAndServe blocks until ctx is cancelled, then shuts down gracefully.
func (s *Server) ListenAndServe(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		var err error
		switch {
		case s.cfg.ServesTLS() && s.http.TLSConfig != nil:
			s.log.Info("listening", "addr", s.cfg.ListenAddr, "tls", true, "tls_mode", s.cfg.TLSMode)
			err = s.http.ListenAndServeTLS("", "")
		case s.cfg.ServesTLS():
			s.log.Info("listening", "addr", s.cfg.ListenAddr, "tls", true)
			err = s.http.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
		default:
			s.log.Warn("listening without TLS; acceptable only behind a TLS-terminating proxy on loopback or a private container network", "addr", s.cfg.ListenAddr)
			err = s.http.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			errCh <- bindHint(err, s.cfg.ListenAddr)
		}
		close(errCh)
	}()
	redirectErr := make(chan error, 1)
	if s.redirect != nil {
		go func() {
			s.log.Info("redirecting plain HTTP to HTTPS", "addr", s.cfg.RedirectAddr)
			if err := s.redirect.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				redirectErr <- bindHint(err, s.cfg.RedirectAddr)
			}
		}()
	}

	shutdown := func() error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		if s.redirect != nil {
			_ = s.redirect.Shutdown(shutdownCtx)
		}
		return s.http.Shutdown(shutdownCtx)
	}
	select {
	case err := <-errCh:
		if s.redirect != nil {
			_ = s.redirect.Close()
		}
		return err
	case err := <-redirectErr:
		_ = s.http.Close()
		return err
	case <-ctx.Done():
		return shutdown()
	}
}

// ---- system handlers

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		s.log.Error("readiness: database ping failed", "err", err)
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "database unavailable"})
		return
	}
	pending, err := store.Pending(ctx, s.db)
	if err != nil || len(pending) > 0 {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "migrations pending", "pending": pending})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"version": version.Version})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, http.StatusNotFound, "not_found", "no such route")
}

// ---- middleware

type middleware func(http.Handler) http.Handler

// chain applies middlewares so that the first listed is the outermost.
func chain(h http.Handler, mws ...middleware) http.Handler {
	for _, mw := range slices.Backward(mws) {
		h = mw(h)
	}
	return h
}

// requestID assigns a fresh random id to every request. Client-supplied ids
// are ignored on purpose: they would let a caller forge log correlation.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b [8]byte
		_, _ = rand.Read(b[:])
		id := hex.EncodeToString(b[:])
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(httpx.WithRequestID(r.Context(), id)))
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
		if s.cfg.ServesTLS() {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// quietPaths are polled by health checks and by the console itself; at
// info they would flood the log (and the console's in-memory ring) with
// their own traffic, so they are logged at debug.
var quietPaths = map[string]bool{
	"/healthz": true, "/readyz": true,
	"/api/v1/admin/logs": true, "/api/v1/admin/system/status": true,
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := httpx.NewStatusRecorder(w)
		next.ServeHTTP(rec, r)
		level := slog.LevelInfo
		if quietPaths[r.URL.Path] && rec.Status < 400 {
			level = slog.LevelDebug
		}
		// Query strings are intentionally not logged: connect tickets travel there.
		s.log.Log(r.Context(), level, "http",
			"request_id", httpx.RequestID(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.Status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", auth.ClientIP(r),
		)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic", "request_id", httpx.RequestID(r.Context()), "panic", rec)
				httpx.WriteError(w, r, http.StatusInternalServerError, "internal", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
