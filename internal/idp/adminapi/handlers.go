// SPDX-License-Identifier: Apache-2.0

// Package adminapi serves /api/v1/identity-providers for admins.
package adminapi

import (
	"context"
	"errors"
	"log/slog"
	"maps"
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
	// Sync runs the directory user sync (ADR 0035); nil leaves its routes
	// answering that there is none.
	Sync *idp.Syncer
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
	mux.Handle("GET /api/v1/identity-providers/{id}/sync", admin(http.HandlerFunc(h.syncStatus)))
	mux.Handle("POST /api/v1/identity-providers/{id}/sync", admin(http.HandlerFunc(h.syncNow)))
	mux.Handle("POST /api/v1/identity-providers/{id}/scim-token", admin(http.HandlerFunc(h.newSCIMToken)))
	mux.Handle("DELETE /api/v1/identity-providers/{id}/scim-token", admin(http.HandlerFunc(h.revokeSCIMToken)))
}

// newSCIMToken makes the provider a SCIM bearer token, replacing any earlier
// one, and answers with it and the base URL to give the provider. The token
// is shown this once: only its hash is kept.
func (h *AdminHandler) newSCIMToken(w http.ResponseWriter, r *http.Request) {
	p, err := h.Providers.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	token, hash, err := idp.NewSCIMToken()
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	replaced := p.SCIMTokenAt != nil
	now := time.Now().UTC()
	if err := h.Providers.SetSCIMToken(r.Context(), p.ID, hash, now); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.IdPSCIMToken, p, map[string]any{"change": "created", "replaced": replaced})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"token": token, "created_at": now, "base_path": "/api/v1/scim/" + p.ID})
}

func (h *AdminHandler) revokeSCIMToken(w http.ResponseWriter, r *http.Request) {
	p, err := h.Providers.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.Providers.ClearSCIMToken(r.Context(), p.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.IdPSCIMToken, p, map[string]any{"change": "revoked"})
	w.WriteHeader(http.StatusNoContent)
}

// syncView is the state of a provider's user sync.
type syncView struct {
	Enabled bool            `json:"enabled"`
	Minutes int             `json:"interval_minutes"`
	Running bool            `json:"running"`
	Last    *idp.SyncStatus `json:"last"`
}

func (h *AdminHandler) syncView(op *idp.Opened) syncView {
	v := syncView{Enabled: op.Config.SyncUsers, Minutes: op.Config.SyncMinutes}
	if h.Sync != nil {
		v.Running, v.Last = h.Sync.Running(op.ID), h.Sync.Status(op.ID)
	}
	return v
}

func (h *AdminHandler) syncStatus(w http.ResponseWriter, r *http.Request) {
	op, err := h.Providers.Open(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.syncView(op))
}

type syncRequest struct {
	// ApplyRemovals disables the accounts a run held back because there
	// were too many at once.
	ApplyRemovals bool `json:"apply_removals"`
}

// syncNow runs the sync for one provider while the administrator waits,
// and answers with what it did. The run is audited under the administrator
// even when it changes nothing.
func (h *AdminHandler) syncNow(w http.ResponseWriter, r *http.Request) {
	var req syncRequest
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(r, &req); err != nil {
			httpx.BadRequest(w, r, err.Error())
			return
		}
	}
	op, err := h.Providers.Open(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	switch {
	case h.Sync == nil:
		httpx.WriteError(w, r, http.StatusConflict, "sync_unavailable", "this gateway does not run the user sync")
		return
	case !op.Enabled || !op.Config.SyncUsers:
		httpx.WriteError(w, r, http.StatusConflict, "sync_off", "turn on user sync for this provider, and enable it, first")
		return
	}
	_, err = h.Sync.Sync(r.Context(), op, idp.SyncOptions{Force: req.ApplyRemovals, Actor: auth.ActorFor(r), Manual: true})
	switch {
	case errors.Is(err, idp.ErrSyncRunning):
		httpx.WriteError(w, r, http.StatusConflict, "sync_running", "a sync of this provider is running; try again when it ends")
		return
	case errors.Is(err, idp.ErrNoDirectory):
		httpx.WriteError(w, r, http.StatusConflict, "sync_unavailable", "this provider cannot be listed")
		return
	}
	// A run that failed still answers 200: the run happened, and its status
	// says what went wrong.
	httpx.WriteJSON(w, http.StatusOK, h.syncView(op))
}

type input struct {
	Name    string     `json:"name"`
	Type    idp.Type   `json:"type,omitempty"`
	Enabled *bool      `json:"enabled"`
	Config  idp.Config `json:"config"`
}

// view is the response shape: the row plus its config with secrets blanked,
// and the state of its user sync when it has one turned on.
type view struct {
	idp.Provider
	Config    idp.Config `json:"config"`
	HasSecret bool       `json:"has_secret"`
	Sync      *syncView  `json:"sync,omitempty"`
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
		v := redact(op)
		if op.Config.SyncUsers {
			sv := h.syncView(op)
			v.Sync = &sv
		}
		out = append(out, v)
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
		httpx.BadRequest(w, r, err.Error())
		return
	}
	p := &idp.Provider{Name: in.Name, Type: in.Type, Enabled: in.Enabled == nil || *in.Enabled}
	cfg := in.Config
	if err := h.Providers.Create(r.Context(), p, &cfg); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.IdPCreate, p, map[string]any{"config": idp.AccessSummary(&cfg)})
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
		httpx.BadRequest(w, r, err.Error())
		return
	}
	cur, err := h.Providers.Open(r.Context(), r.PathValue("id"))
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
	op, err := h.Providers.Open(r.Context(), p.ID)
	details := map[string]any{"previous": idp.AccessSummary(&cur.Config), "previous_enabled": cur.Enabled}
	if err == nil {
		details["config"] = idp.AccessSummary(&op.Config)
	}
	h.record(r, audit.IdPUpdate, p, details)
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
	h.record(r, audit.IdPDelete, p, nil)
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
	h.recordOutcome(r, audit.IdPTest, &op.Provider, outcome, nil)
	status := http.StatusOK
	if terr != nil {
		status = http.StatusBadGateway
	}
	httpx.WriteJSON(w, status, result)
}

func (h *AdminHandler) record(r *http.Request, action string, p *idp.Provider, extra map[string]any) {
	h.recordOutcome(r, action, p, audit.Success, extra)
}

func (h *AdminHandler) recordOutcome(r *http.Request, action string, p *idp.Provider, outcome audit.Outcome, extra map[string]any) {
	details := map[string]any{"name": p.Name, "type": p.Type, "enabled": p.Enabled}
	maps.Copy(details, extra)
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(action, "identity_provider", p.ID, outcome, details))
}

func (h *AdminHandler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, idp.ErrNotFound):
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "identity provider not found")
	case errors.Is(err, idp.ErrDuplicate):
		httpx.WriteError(w, r, http.StatusConflict, "conflict", "a provider with that name exists")
	case errors.Is(err, idp.ErrInvalidInput):
		httpx.BadRequest(w, r, err.Error())
	default:
		httpx.Internal(w, r, h.Log, err)
	}
}
