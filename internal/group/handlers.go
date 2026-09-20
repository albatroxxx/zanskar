// SPDX-License-Identifier: Apache-2.0

package group

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

// AdminHandler serves /api/v1/groups.
type AdminHandler struct {
	Groups *Repo
	Audit  *audit.Log
	Log    *slog.Logger
}

// Register mounts the routes behind the admin role.
func (h *AdminHandler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/groups", admin(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/v1/groups", admin(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/v1/groups/{id}", admin(http.HandlerFunc(h.get)))
	mux.Handle("PUT /api/v1/groups/{id}", admin(http.HandlerFunc(h.update)))
	mux.Handle("DELETE /api/v1/groups/{id}", admin(http.HandlerFunc(h.del)))
	mux.Handle("GET /api/v1/groups/{id}/members", admin(http.HandlerFunc(h.members)))
	mux.Handle("PUT /api/v1/groups/{id}/members", admin(http.HandlerFunc(h.setMembers)))
}

type groupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type membersRequest struct {
	UserIDs []string `json:"user_ids"`
}

type detail struct {
	*Group
	Members []Member `json:"members"`
}

func (h *AdminHandler) list(w http.ResponseWriter, r *http.Request) {
	limit, cursor := httpx.Paging(r, 50, 500)
	groups, next, err := h.Groups.List(r.Context(), cursor, limit)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[*Group]{Items: groups, NextCursor: next})
}

func (h *AdminHandler) create(w http.ResponseWriter, r *http.Request) {
	var req groupRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	g := &Group{Name: strings.TrimSpace(req.Name), Description: req.Description}
	if err := h.Groups.Create(r.Context(), g); err != nil {
		h.writeGroupError(w, r, err)
		return
	}
	h.record(r, "group.create", g.ID, map[string]any{"name": g.Name})
	httpx.WriteJSON(w, http.StatusCreated, g)
}

func (h *AdminHandler) get(w http.ResponseWriter, r *http.Request) {
	g, err := h.Groups.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeGroupError(w, r, err)
		return
	}
	members, err := h.Groups.Members(r.Context(), g.ID)
	if err != nil {
		h.writeGroupError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, detail{Group: g, Members: members})
}

func (h *AdminHandler) update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req groupRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	before, err := h.Groups.Get(r.Context(), id)
	if err != nil {
		h.writeGroupError(w, r, err)
		return
	}
	if req.Name == "" {
		req.Name = before.Name
	}
	if err := h.Groups.Update(r.Context(), id, req.Name, req.Description); err != nil {
		h.writeGroupError(w, r, err)
		return
	}
	h.record(r, "group.update", id, map[string]any{"name": req.Name, "previous_name": before.Name})
	g, err := h.Groups.Get(r.Context(), id)
	if err != nil {
		h.writeGroupError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, g)
}

func (h *AdminHandler) del(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	g, err := h.Groups.Get(r.Context(), id)
	if err != nil {
		h.writeGroupError(w, r, err)
		return
	}
	if err := h.Groups.Delete(r.Context(), id); err != nil {
		h.writeGroupError(w, r, err)
		return
	}
	h.record(r, "group.delete", id, map[string]any{"name": g.Name, "member_count": g.MemberCount})
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) members(w http.ResponseWriter, r *http.Request) {
	members, err := h.Groups.Members(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeGroupError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": members})
}

func (h *AdminHandler) setMembers(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req membersRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if req.UserIDs == nil {
		httpx.BadRequest(w, "user_ids is required")
		return
	}
	added, removed, err := h.Groups.SetMembers(r.Context(), id, req.UserIDs)
	if err != nil {
		h.writeGroupError(w, r, err)
		return
	}
	h.record(r, "group.members.update", id, map[string]any{"added": added, "removed": removed})
	members, err := h.Groups.Members(r.Context(), id)
	if err != nil {
		h.writeGroupError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": members})
}

func (h *AdminHandler) record(r *http.Request, action, objectID string, details any) {
	if h.Audit == nil {
		return
	}
	actor := audit.Actor{IP: auth.ClientIP(r)}
	if p, ok := auth.FromContext(r.Context()); ok {
		actor.UserID = p.User.ID
	}
	if _, err := h.Audit.Record(r.Context(), actor.Event(action, "group", objectID, audit.Success, details)); err != nil {
		h.Log.Error("audit record failed", "action", action, "err", err)
	}
}

func (h *AdminHandler) writeGroupError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "no such group")
	case errors.Is(err, ErrDuplicate):
		httpx.WriteError(w, http.StatusConflict, "conflict", "group name already exists")
	case errors.Is(err, ErrSynced):
		httpx.WriteError(w, http.StatusConflict, "synced", "membership is managed by an identity provider")
	case errors.Is(err, ErrInvalidInput):
		httpx.BadRequest(w, err.Error())
	default:
		h.serverError(w, r, err)
	}
}

func (h *AdminHandler) serverError(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.Error("groups admin handler", "path", r.URL.Path, "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
}
