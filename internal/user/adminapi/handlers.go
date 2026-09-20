// SPDX-License-Identifier: Apache-2.0

// Package adminapi serves the admin endpoints for user management. It lives
// beside package user rather than inside it because package auth imports
// user, and these handlers need auth's middleware.
package adminapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

// SessionRevoker ends a user's browser sessions.
type SessionRevoker interface {
	RevokeAllForUser(ctx context.Context, userID string) (int64, error)
}

// MFAResetter removes a user's authenticator.
type MFAResetter interface {
	Reset(ctx context.Context, userID string) error
}

// AdminHandler serves /api/v1/users.
type AdminHandler struct {
	Users    *user.Repo
	Sessions SessionRevoker
	TOTP     MFAResetter
	Audit    *audit.Log
	Log      *slog.Logger
}

// Register mounts the routes behind the admin role.
func (h *AdminHandler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/users", admin(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/v1/users", admin(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/v1/users/{id}", admin(http.HandlerFunc(h.get)))
	mux.Handle("PUT /api/v1/users/{id}", admin(http.HandlerFunc(h.update)))
	mux.Handle("PUT /api/v1/users/{id}/roles", admin(http.HandlerFunc(h.setRoles)))
	mux.Handle("PUT /api/v1/users/{id}/password", admin(http.HandlerFunc(h.setPassword)))
	mux.Handle("DELETE /api/v1/users/{id}/sessions", admin(http.HandlerFunc(h.revokeSessions)))
	mux.Handle("DELETE /api/v1/users/{id}/mfa", admin(http.HandlerFunc(h.resetMFA)))
	mux.Handle("DELETE /api/v1/users/{id}", admin(http.HandlerFunc(h.del)))
}

type createRequest struct {
	Username           string      `json:"username"`
	DisplayName        string      `json:"display_name"`
	Email              string      `json:"email"`
	Roles              []user.Role `json:"roles"`
	Password           string      `json:"password"`
	MustChangePassword *bool       `json:"must_change_password"`
}

type updateRequest struct {
	DisplayName string      `json:"display_name"`
	Email       string      `json:"email"`
	Status      user.Status `json:"status"`
}

type rolesRequest struct {
	Roles []user.Role `json:"roles"`
}

type passwordRequest struct {
	Password string `json:"password"`
}

func (h *AdminHandler) list(w http.ResponseWriter, r *http.Request) {
	limit, cursor := httpx.Paging(r, 50, 500)
	users, next, err := h.Users.List(r.Context(), cursor, limit)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	if users == nil {
		users = []*user.User{}
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[*user.User]{Items: users, NextCursor: next})
}

func (h *AdminHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if len(req.Roles) == 0 {
		httpx.BadRequest(w, "at least one role is required")
		return
	}
	u := &user.User{
		Username:    strings.TrimSpace(req.Username),
		DisplayName: strings.TrimSpace(req.DisplayName),
		Email:       req.Email,
		Roles:       req.Roles,
	}
	if req.Password != "" {
		if err := user.CheckPasswordPolicy(req.Password); err != nil {
			httpx.BadRequest(w, err.Error())
			return
		}
		hash, err := user.HashPassword(req.Password)
		if err != nil {
			h.serverError(w, r, err)
			return
		}
		u.PasswordHash = hash
	}
	if err := h.Users.Create(r.Context(), u); err != nil {
		h.writeUserError(w, r, err)
		return
	}
	details := map[string]any{"username": u.Username, "roles": u.Roles, "has_password": u.PasswordHash != ""}
	if granted := privileged(u.Roles); len(granted) > 0 {
		details["roles_granted"] = granted
	}
	h.record(r, "user.create", u.ID, audit.Success, details)
	httpx.WriteJSON(w, http.StatusCreated, u)
}

func (h *AdminHandler) get(w http.ResponseWriter, r *http.Request) {
	u, err := h.Users.GetByID(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeUserError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *AdminHandler) update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req updateRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	existing, err := h.Users.GetByID(r.Context(), id)
	if err != nil {
		h.writeUserError(w, r, err)
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = existing.DisplayName
	}
	if req.Status == "" {
		req.Status = existing.Status
	}
	if req.Status != user.StatusActive && h.isSelf(r, id) {
		httpx.WriteError(w, http.StatusConflict, "self", "you cannot disable or lock your own account")
		return
	}
	if err := h.Users.Update(r.Context(), id, req.DisplayName, req.Email, req.Status); err != nil {
		h.writeUserError(w, r, err)
		return
	}
	if req.Status != user.StatusActive && existing.Status == user.StatusActive {
		if _, err := h.Sessions.RevokeAllForUser(r.Context(), id); err != nil {
			h.Log.Error("revoke sessions after status change", "user_id", id, "err", err)
		}
	}
	h.record(r, "user.update", id, audit.Success, map[string]any{
		"display_name": req.DisplayName, "email": req.Email, "status": req.Status, "previous_status": existing.Status,
	})
	u, err := h.Users.GetByID(r.Context(), id)
	if err != nil {
		h.writeUserError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *AdminHandler) setRoles(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req rolesRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if len(req.Roles) == 0 {
		httpx.BadRequest(w, "at least one role is required")
		return
	}
	before, err := h.Users.GetByID(r.Context(), id)
	if err != nil {
		h.writeUserError(w, r, err)
		return
	}
	if err := h.Users.SetRoles(r.Context(), id, req.Roles); err != nil {
		h.writeUserError(w, r, err)
		return
	}
	details := map[string]any{"roles": req.Roles, "previous_roles": before.Roles}
	var granted []user.Role
	for _, role := range privileged(req.Roles) {
		if !before.HasRole(role) {
			granted = append(granted, role)
		}
	}
	if len(granted) > 0 {
		details["roles_granted"] = granted
	}
	h.record(r, "user.roles.update", id, audit.Success, details)
	u, err := h.Users.GetByID(r.Context(), id)
	if err != nil {
		h.writeUserError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *AdminHandler) setPassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req passwordRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if err := user.CheckPasswordPolicy(req.Password); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	hash, err := user.HashPassword(req.Password)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	if err := h.Users.SetPasswordHash(r.Context(), id, hash); err != nil {
		h.writeUserError(w, r, err)
		return
	}
	n, err := h.Sessions.RevokeAllForUser(r.Context(), id)
	if err != nil {
		h.Log.Error("revoke sessions after password reset", "user_id", id, "err", err)
	}
	h.record(r, "user.password.reset", id, audit.Success, map[string]any{"sessions_revoked": n})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok", "sessions_revoked": n})
}

func (h *AdminHandler) revokeSessions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := h.Users.GetByID(r.Context(), id); err != nil {
		h.writeUserError(w, r, err)
		return
	}
	n, err := h.Sessions.RevokeAllForUser(r.Context(), id)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	h.record(r, "user.sessions.revoke", id, audit.Success, map[string]any{"sessions_revoked": n})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok", "sessions_revoked": n})
}

func (h *AdminHandler) resetMFA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := h.Users.GetByID(r.Context(), id); err != nil {
		h.writeUserError(w, r, err)
		return
	}
	if err := h.TOTP.Reset(r.Context(), id); err != nil {
		h.serverError(w, r, err)
		return
	}
	// A session that passed MFA with the old authenticator should not outlive it.
	n, err := h.Sessions.RevokeAllForUser(r.Context(), id)
	if err != nil {
		h.Log.Error("revoke sessions after mfa reset", "user_id", id, "err", err)
	}
	h.record(r, "user.mfa.reset", id, audit.Success, map[string]any{"sessions_revoked": n})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok", "sessions_revoked": n})
}

func (h *AdminHandler) del(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if h.isSelf(r, id) {
		httpx.WriteError(w, http.StatusConflict, "self", "you cannot delete your own account")
		return
	}
	u, err := h.Users.GetByID(r.Context(), id)
	if err != nil {
		h.writeUserError(w, r, err)
		return
	}
	if _, err := h.Sessions.RevokeAllForUser(r.Context(), id); err != nil {
		h.Log.Error("revoke sessions before delete", "user_id", id, "err", err)
	}
	if err := h.Users.Delete(r.Context(), id); err != nil {
		h.writeUserError(w, r, err)
		return
	}
	h.record(r, "user.delete", id, audit.Success, map[string]any{"username": u.Username, "roles": u.Roles})
	w.WriteHeader(http.StatusNoContent)
}

// ---- helpers

func privileged(roles []user.Role) []user.Role {
	var out []user.Role
	for _, role := range roles {
		if role == user.RoleAdmin || role == user.RoleAuditor {
			out = append(out, role)
		}
	}
	return out
}

func (h *AdminHandler) isSelf(r *http.Request, id string) bool {
	p, ok := auth.FromContext(r.Context())
	return ok && p.User.ID == id
}

//nolint:unparam // outcome is always success today; failure paths will use it
func (h *AdminHandler) record(r *http.Request, action, objectID string, outcome audit.Outcome, details any) {
	if h.Audit == nil {
		return
	}
	actor := audit.Actor{IP: auth.ClientIP(r)}
	if p, ok := auth.FromContext(r.Context()); ok {
		actor.UserID = p.User.ID
	}
	if _, err := h.Audit.Record(r.Context(), actor.Event(action, "user", objectID, outcome, details)); err != nil {
		h.Log.Error("audit record failed", "action", action, "err", err)
	}
}

func (h *AdminHandler) writeUserError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, user.ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "no such user")
	case errors.Is(err, user.ErrDuplicate):
		httpx.WriteError(w, http.StatusConflict, "conflict", "username or email already exists")
	case errors.Is(err, user.ErrLastAdmin):
		httpx.WriteError(w, http.StatusConflict, "last_admin", "this is the last active admin")
	case errors.Is(err, user.ErrInvalidRole), errors.Is(err, user.ErrUsernameShape),
		errors.Is(err, user.ErrInvalidInput), errors.Is(err, user.ErrWeakPassword):
		httpx.BadRequest(w, err.Error())
	default:
		h.serverError(w, r, err)
	}
}

func (h *AdminHandler) serverError(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.Error("users admin handler", "path", r.URL.Path, "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
}
