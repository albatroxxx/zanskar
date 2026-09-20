// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

// AdminHandler serves /api/v1/access-policies for admins.
type AdminHandler struct {
	Repo  *Repo
	Audit *audit.Log
	Log   *slog.Logger
}

// Register mounts the routes.
func (h *AdminHandler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/access-policies", admin(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/v1/access-policies", admin(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/v1/access-policies/{id}", admin(http.HandlerFunc(h.get)))
	mux.Handle("PUT /api/v1/access-policies/{id}", admin(http.HandlerFunc(h.update)))
	mux.Handle("DELETE /api/v1/access-policies/{id}", admin(http.HandlerFunc(h.del)))
}

// input is the request body for create and update.
type input struct {
	Name               string       `json:"name"`
	Description        string       `json:"description"`
	Enabled            *bool        `json:"enabled"`
	GroupID            string       `json:"group_id"`
	Selector           Selector     `json:"target_selector"`
	Protocols          []string     `json:"protocols"`
	TimeWindows        []TimeWindow `json:"time_windows"`
	MaxSessionMinutes  *int         `json:"max_session_minutes"`
	IdleTimeoutMinutes *int         `json:"idle_timeout_minutes"`
	AllowClipboard     *bool        `json:"allow_clipboard"`
	AllowFileTransfer  *bool        `json:"allow_file_transfer"`
	RequireMFA         *bool        `json:"require_mfa"`
}

func (in *input) apply(p *Policy) {
	p.Name, p.Description, p.GroupID = in.Name, in.Description, in.GroupID
	p.Selector, p.Protocols, p.TimeWindows, p.MaxSessionMinutes = in.Selector, in.Protocols, in.TimeWindows, in.MaxSessionMinutes
	p.Enabled = in.Enabled == nil || *in.Enabled
	p.IdleTimeoutMinutes = 15
	if in.IdleTimeoutMinutes != nil {
		p.IdleTimeoutMinutes = *in.IdleTimeoutMinutes
	}
	p.AllowClipboard = in.AllowClipboard != nil && *in.AllowClipboard
	p.AllowFileTransfer = in.AllowFileTransfer != nil && *in.AllowFileTransfer
	p.RequireMFA = in.RequireMFA == nil || *in.RequireMFA
}

func (h *AdminHandler) list(w http.ResponseWriter, r *http.Request) {
	limit, cursor := httpx.Paging(r, 50, 500)
	items, next, err := h.Repo.List(r.Context(), cursor, limit)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[*Policy]{Items: items, NextCursor: next})
}

func (h *AdminHandler) get(w http.ResponseWriter, r *http.Request) {
	p, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *AdminHandler) create(w http.ResponseWriter, r *http.Request) {
	var in input
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	pr, _ := auth.FromContext(r.Context())
	p := &Policy{CreatedBy: pr.User.ID}
	in.apply(p)
	if err := h.Repo.Create(r.Context(), p); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "policy.create", p)
	httpx.WriteJSON(w, http.StatusCreated, p)
}

func (h *AdminHandler) update(w http.ResponseWriter, r *http.Request) {
	var in input
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	p, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	in.apply(p)
	if err := h.Repo.Update(r.Context(), p); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "policy.update", p)
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *AdminHandler) del(w http.ResponseWriter, r *http.Request) {
	p, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.Repo.Delete(r.Context(), p.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "policy.delete", p)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) record(r *http.Request, action string, p *Policy) {
	if h.Audit == nil {
		return
	}
	pr, _ := auth.FromContext(r.Context())
	actor := audit.Actor{UserID: pr.User.ID, IP: auth.ClientIP(r)}
	details := map[string]any{"name": p.Name, "group_id": p.GroupID, "protocols": p.Protocols, "selector": p.Selector, "enabled": p.Enabled}
	if _, err := h.Audit.Record(r.Context(), actor.Event(action, "access_policy", p.ID, audit.Success, details)); err != nil {
		h.Log.Error("audit record failed", "action", action, "err", err)
	}
}

func (h *AdminHandler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "policy not found")
	case errors.Is(err, ErrDuplicate):
		httpx.WriteError(w, http.StatusConflict, "conflict", "a policy with that name exists")
	case errors.Is(err, ErrInvalidInput):
		httpx.BadRequest(w, err.Error())
	default:
		h.Log.Error("policy handler", "path", r.URL.Path, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}
