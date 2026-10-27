// SPDX-License-Identifier: Apache-2.0

package tlscert

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Handler serves the admin routes for the gateway's certificate.
type Handler struct {
	Manager *Manager
	// Mode is the config's TLS mode; in proxy mode there is nothing to
	// manage and the routes say so.
	Mode  string
	Audit *audit.Log
	Log   *slog.Logger
}

// Register mounts the routes; all admin-only.
func (h *Handler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/admin/tls", admin(http.HandlerFunc(h.get)))
	mux.Handle("PUT /api/v1/admin/tls", admin(http.HandlerFunc(h.upload)))
	mux.Handle("DELETE /api/v1/admin/tls", admin(http.HandlerFunc(h.reset)))
	mux.Handle("POST /api/v1/admin/tls/self-signed", admin(http.HandlerFunc(h.regenerate)))
}

// Status is what the console shows.
type Status struct {
	Mode      string `json:"mode"` // file | managed | proxy
	Active    *Info  `json:"active,omitempty"`
	Uploaded  *Info  `json:"uploaded,omitempty"`
	Generated *Info  `json:"generated,omitempty"`
	// FileHint names the variables for the file certificate, when one is in use.
	FileHint string `json:"file_hint,omitempty"`
}

func (h *Handler) status(r *http.Request) Status {
	s := Status{Mode: h.Mode}
	if h.Mode == "proxy" || h.Manager == nil {
		return s
	}
	a := h.Manager.Active()
	s.Active = &a
	if u, err := h.Manager.Uploaded(r.Context()); err == nil {
		s.Uploaded = &u
	}
	if g, err := h.Manager.Generated(r.Context()); err == nil {
		s.Generated = &g
	}
	if h.Manager.File != nil {
		s.FileHint = "ZANSKAR_TLS_CERT, ZANSKAR_TLS_KEY"
	}
	return s
}

// pem reads the certificate and key of an upload body.
func (h *Handler) pem(w http.ResponseWriter, r *http.Request) (certPEM, keyPEM string, ok bool) {
	var in struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return "", "", false
	}
	if strings.TrimSpace(in.CertPEM) == "" || strings.TrimSpace(in.KeyPEM) == "" {
		httpx.BadRequest(w, r, "cert_pem and key_pem are required")
		return "", "", false
	}
	return in.CertPEM, in.KeyPEM, true
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.status(r))
}

func (h *Handler) managed(w http.ResponseWriter, r *http.Request) bool {
	if h.Mode == "proxy" || h.Manager == nil {
		httpx.WriteError(w, r, http.StatusConflict, "tls_proxy", "TLS is terminated by the proxy in front of the gateway (ZANSKAR_TLS_MODE=proxy); manage the certificate there")
		return false
	}
	return true
}

func (h *Handler) upload(w http.ResponseWriter, r *http.Request) {
	if !h.managed(w, r) {
		return
	}
	certPEM, keyPEM, ok := h.pem(w, r)
	if !ok {
		return
	}
	p, _ := auth.FromContext(r.Context())
	info, err := h.Manager.Upload(r.Context(), certPEM, keyPEM, p.User.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// The key is never recorded; the certificate is public.
	h.record(r, audit.TLSCertificateUpload, map[string]any{"subject": info.Subject, "hosts": info.Hosts, "not_after": info.NotAfter, "fingerprint": info.Fingerprint})
	httpx.WriteJSON(w, http.StatusOK, h.status(r))
}

func (h *Handler) reset(w http.ResponseWriter, r *http.Request) {
	if !h.managed(w, r) {
		return
	}
	before := h.Manager.Active()
	info, err := h.Manager.Reset(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.TLSCertificateReset, map[string]any{"before": before.Fingerprint, "after": info.Fingerprint, "after_source": info.Source})
	httpx.WriteJSON(w, http.StatusOK, h.status(r))
}

func (h *Handler) regenerate(w http.ResponseWriter, r *http.Request) {
	if !h.managed(w, r) {
		return
	}
	var in struct {
		Hosts []string `json:"hosts"`
	}
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(r, &in); err != nil {
			httpx.BadRequest(w, r, err.Error())
			return
		}
	}
	hosts := dedupe(in.Hosts)
	if len(hosts) == 0 {
		hosts = h.Manager.Hosts
	}
	if len(hosts) > 32 {
		httpx.BadRequest(w, r, "at most 32 hosts")
		return
	}
	for _, host := range hosts {
		if err := ValidHost(host); err != nil {
			h.fail(w, r, err)
			return
		}
	}
	p, _ := auth.FromContext(r.Context())
	if err := h.Manager.Regenerate(r.Context(), hosts, p.User.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	g, _ := h.Manager.Generated(r.Context())
	h.record(r, audit.TLSCertificateRegenerate, map[string]any{"hosts": hosts, "fingerprint": g.Fingerprint, "serving": h.Manager.Active().Source == SourceGenerated})
	httpx.WriteJSON(w, http.StatusOK, h.status(r))
}

func (h *Handler) record(r *http.Request, action string, details map[string]any) {
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(action, "tls_certificate", "gateway", audit.Success, details))
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrInvalid) {
		httpx.BadRequest(w, r, strings.TrimPrefix(err.Error(), "tlscert: invalid certificate: "))
		return
	}
	httpx.Internal(w, r, h.Log, err)
}
