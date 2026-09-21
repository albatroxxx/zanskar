// SPDX-License-Identifier: Apache-2.0

// Package adminapi serves /api/v1/identity-providers for admins.
package adminapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/idp"
	"github.com/albatroxxx/zanskar/internal/user"
)

// LDAPTester checks an LDAP configuration by binding to the directory.
type LDAPTester interface {
	Test(ctx context.Context, cfg *idp.LDAPConfig) error
}

// AdminHandler manages identity providers.
type AdminHandler struct {
	Providers  *idp.Repo
	Audit      *audit.Log
	Log        *slog.Logger
	LDAPTester LDAPTester
	// HTTPClient for OIDC discovery in tests; defaults to a 10 s client.
	HTTPClient *http.Client
}

// Register mounts the routes.
func (h *AdminHandler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/identity-providers", admin(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/v1/identity-providers", admin(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/v1/identity-providers/{id}", admin(http.HandlerFunc(h.get)))
	mux.Handle("PUT /api/v1/identity-providers/{id}", admin(http.HandlerFunc(h.update)))
	mux.Handle("DELETE /api/v1/identity-providers/{id}", admin(http.HandlerFunc(h.del)))
	mux.Handle("POST /api/v1/identity-providers/{id}/test", admin(http.HandlerFunc(h.test)))
}

type input struct {
	Name    string     `json:"name"`
	Type    idp.Type   `json:"type,omitempty"`
	Enabled *bool      `json:"enabled"`
	Config  idp.Config `json:"config"`
}

// view is the response shape: the row plus its config with secrets blanked.
type view struct {
	idp.Provider
	Config    idp.Config `json:"config"`
	HasSecret bool       `json:"has_secret"`
}

func redact(op *idp.Opened) view {
	v := view{Provider: op.Provider, Config: op.Config}
	if v.Config.OIDC != nil {
		o := *v.Config.OIDC
		v.HasSecret = o.ClientSecret != ""
		o.ClientSecret = ""
		v.Config.OIDC = &o
	}
	if v.Config.LDAP != nil {
		l := *v.Config.LDAP
		v.HasSecret = l.BindPassword != ""
		l.BindPassword = ""
		v.Config.LDAP = &l
	}
	return v
}

func (h *AdminHandler) list(w http.ResponseWriter, r *http.Request) {
	ps, err := h.Providers.List(r.Context(), false)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := make([]view, 0, len(ps))
	for _, p := range ps {
		op, err := h.Providers.Open(r.Context(), p.ID)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		out = append(out, redact(op))
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[view]{Items: out})
}

func (h *AdminHandler) get(w http.ResponseWriter, r *http.Request) {
	op, err := h.Providers.Open(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, redact(op))
}

func (h *AdminHandler) create(w http.ResponseWriter, r *http.Request) {
	var in input
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	p := &idp.Provider{Name: in.Name, Type: in.Type, Enabled: in.Enabled == nil || *in.Enabled}
	cfg := in.Config
	if err := h.Providers.Create(r.Context(), p, &cfg); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "idp.create", p)
	op, err := h.Providers.Open(r.Context(), p.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, redact(op))
}

func (h *AdminHandler) update(w http.ResponseWriter, r *http.Request) {
	var in input
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	cur, err := h.Providers.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	p := &idp.Provider{ID: cur.ID, Name: in.Name, Type: cur.Type, Enabled: cur.Enabled}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
	cfg := in.Config
	if err := h.Providers.Update(r.Context(), p, &cfg); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "idp.update", p)
	op, err := h.Providers.Open(r.Context(), p.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, redact(op))
}

func (h *AdminHandler) del(w http.ResponseWriter, r *http.Request) {
	p, err := h.Providers.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.Providers.Delete(r.Context(), p.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "idp.delete", p)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) test(w http.ResponseWriter, r *http.Request) {
	op, err := h.Providers.Open(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	result := map[string]any{"status": "ok"}
	var terr error
	switch op.Type {
	case idp.TypeOIDC:
		client := h.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: 10 * time.Second}
		}
		ctx, cancel := context.WithTimeout(gooidc.ClientContext(r.Context(), client), 10*time.Second)
		defer cancel()
		prov, err := gooidc.NewProvider(ctx, op.Config.OIDC.Issuer)
		if err != nil {
			terr = err
		} else {
			ep := prov.Endpoint()
			result["issuer"] = op.Config.OIDC.Issuer
			result["authorization_endpoint"] = ep.AuthURL
			result["token_endpoint"] = ep.TokenURL
		}
	case idp.TypeLDAP:
		if h.LDAPTester == nil {
			result = map[string]any{"status": "skipped", "message": "use the LDAP test in a later release"}
		} else {
			terr = h.LDAPTester.Test(r.Context(), op.Config.LDAP)
		}
	}
	outcome := audit.Success
	if terr != nil {
		outcome = audit.Failure
		result = map[string]any{"status": "failed", "message": terr.Error()}
	}
	h.recordOutcome(r, "idp.test", &op.Provider, outcome)
	status := http.StatusOK
	if terr != nil {
		status = http.StatusBadGateway
	}
	httpx.WriteJSON(w, status, result)
}

func (h *AdminHandler) record(r *http.Request, action string, p *idp.Provider) {
	h.recordOutcome(r, action, p, audit.Success)
}

func (h *AdminHandler) recordOutcome(r *http.Request, action string, p *idp.Provider, outcome audit.Outcome) {
	if h.Audit == nil {
		return
	}
	pr, _ := auth.FromContext(r.Context())
	actor := audit.Actor{UserID: pr.User.ID, IP: auth.ClientIP(r)}
	details := map[string]any{"name": p.Name, "type": p.Type, "enabled": p.Enabled}
	if _, err := h.Audit.Record(r.Context(), actor.Event(action, "identity_provider", p.ID, outcome, details)); err != nil {
		h.Log.Error("audit record failed", "action", action, "err", err)
	}
}

func (h *AdminHandler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, idp.ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "identity provider not found")
	case errors.Is(err, idp.ErrDuplicate):
		httpx.WriteError(w, http.StatusConflict, "conflict", "a provider with that name exists")
	case errors.Is(err, idp.ErrInvalidInput):
		httpx.BadRequest(w, err.Error())
	default:
		h.Log.Error("idp admin handler", "path", r.URL.Path, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}
