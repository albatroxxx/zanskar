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
	// Theme is the console's theme for everyone (display.theme), written
	// into the pre-paint theme script; nil serves the bundle's file as is.
	Theme func() string
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
	if deps.Theme != nil {
		if h := themeScript(web.FS(), deps.Theme); h != nil {
			mux.Handle("GET /theme.js", h)
		}
	}
	if deps.Auth != nil {
		deps.Auth.Register(mux)
	}
	for _, h := range deps.Handlers {
		h.Register(mux)
	}
	// A handler that works through the gateway's own routes (the
	// configuration import, ADR 0043) is handed them once all are in.
	for _, h := range deps.Handlers {
		if u, ok := h.(interface{ UseMux(http.Handler) }); ok {
			u.UseMux(mux)
		}
	}

	// The request id comes first, so even a recovered panic answers and logs
	// with it. RealIP runs before accessLog and the handlers so the forwarded
	// client address, not the proxy's, reaches the log and every audit row.
	// Those three are for every request; the rest are the console's.
	console := []middleware{s.securityHeaders, s.accessLog}
	if deps.AuthMiddleware != nil {
		console = append(console, deps.AuthMiddleware.Authenticate, deps.AuthMiddleware.CSRF)
	}
	root := chain(mux, console...)

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
			covered = deps.TLS.Covered
		}
		s.redirect = newRedirectServer(cfg.RedirectAddr, cfg.ListenAddr, covered)
	}
	return s
}

// plainListenerLevel is how loudly a listener without TLS is logged. An
// operator who set the proxy mode and said the proxy terminates TLS
// (ZANSKAR_TRUST_PROXY_TLS) has configured the supported deployment, so it is
// information; the warning, which every start of that deployment wrote
// (2026-11-04, live), is for a plain listener nobody said a proxy fronts.
func plainListenerLevel(cfg *config.Config) slog.Level {
	if cfg.TLSMode == config.TLSProxy && cfg.TrustProxyTLS {
		return slog.LevelInfo
	}
	return slog.LevelWarn
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
			s.log.Log(ctx, plainListenerLevel(s.cfg), "listening without TLS; acceptable only behind a TLS-terminating proxy on loopback or a private container network", "addr", s.cfg.ListenAddr)
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
		// HSTS whenever the browser reaches the gateway over HTTPS: either we
		// terminate TLS ourselves or a trusted proxy does (SecureCookies covers
		// both). Gating on ServesTLS alone left the reverse-proxy topology, the
		// one the install guide recommends, without HSTS.
		if s.cfg.SecureCookies() {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// quietPaths are polled by health checks and by the console itself; at
// info they would flood the log (and the console's in-memory ring) with
// their own traffic, so they are logged at debug.
//
// The shell reads every console page makes when it opens (who is signed in,
// the update check, the host, the command line, the pending requests, the
// metrics) are listed too: about eight lines a page view, which pushed the
// restart and the update out of the 2000-line ring within minutes (2026-11-05,
// live). Only a served GET is quiet: a change, and anything that fails, is
// logged at info as before.
var quietPaths = map[string]bool{
	"/healthz": true, "/readyz": true,
	"/api/v1/admin/logs": true, "/api/v1/admin/system/status": true,
	"/api/v1/auth/me": true, "/api/v1/access-requests": true,
	"/api/v1/admin/system/update": true, "/api/v1/admin/system/host": true,
	"/api/v1/admin/system/metrics": true, "/api/v1/admin/cli": true,
}

// staticKey carries the mark a request for one of the console's own files
// gets (markStatic), read by the access log.
type staticKey struct{}

// markStatic marks r as a request for a file of the console's bundle: a
// script, a style sheet, a font, an icon. A page load fetches about ten, and
// at info each was a line of its own (the live console, 2026-11-01), so a
// served one is logged at debug. The page itself, and anything that fails,
// stays at info.
func markStatic(r *http.Request) {
	if f, ok := r.Context().Value(staticKey{}).(*bool); ok {
		*f = true
	}
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := httpx.NewStatusRecorder(w)
		static := new(bool)
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), staticKey{}, static)))
		level := slog.LevelInfo
		if ((quietPaths[r.URL.Path] && r.Method == http.MethodGet) || *static) && rec.Status < 400 {
			level = slog.LevelDebug
		}
		// Query strings are intentionally not logged: connect tickets travel there.
		attrs := []any{
			"request_id", httpx.RequestID(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.Status,
			"duration_ms", time.Since(start).Milliseconds(),
		}
		// The client's address only where a request failed, which is when it
		// is wanted (a probe, a flood): a served request's line is the
		// gateway's own traffic, and kept beside its path the address was a
		// trail of where each person went (2026-11-03 live audit, S4). The
		// audit log keeps the address of every sign-in, connect and change.
		if rec.Status >= 400 {
			attrs = append(attrs, "remote", auth.ClientIP(r))
		}
		s.log.Log(r.Context(), level, "http", attrs...)
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
