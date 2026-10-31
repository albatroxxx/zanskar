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
	"github.com/albatroxxx/zanskar/internal/gateway"
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
	// Revoker ends the user's live sessions when their access is withdrawn
	// (ADR 0013); nil leaves them to their own limits.
	Revoker gateway.Revoker
	Audit   *audit.Log
	Log     *slog.Logger
	// ProviderHolds says whether an identity provider still decides who
	// its people are, and its name (idp.Repo.Holds); nil holds nothing.
	ProviderHolds func(ctx context.Context, idpID string) (name string, holds bool, err error)
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
	// GroupIDs makes the new user a member of these groups in the same
	// transaction; optional (2026-10-30).
	GroupIDs         []string    `json:"group_ids"`
	Username         string      `json:"username"`
	DisplayName      string      `json:"display_name"`
	Email            string      `json:"email"`
	Roles            []user.Role `json:"roles"`
	Password         string      `json:"password"`
	MustResetOnLogin *bool       `json:"must_change_password"`
	// PasswordLess creates an account with no password at all, for someone
	// who signs in through an identity provider. Give it the username the
	// provider asserts: the first time a provider authenticates someone
	// under that username, it adopts the account (links it to the provider
	// and the person's external id) and the account keeps the roles set
	// here, whether or not the provider auto-provisions (see
	// idp.Provisioner.Resolve and ADR 0005). Otherwise a one-time password
	// is generated when none is given; an account with a password is never
	// adopted.
	PasswordLess bool `json:"password_less"`
}

// updateRequest changes what it names: a field left out keeps its value.
// Email is a pointer so that leaving it out and clearing it ("") differ.
type updateRequest struct {
	DisplayName string      `json:"display_name"`
	Email       *string     `json:"email"`
	Status      user.Status `json:"status"`
}

type rolesRequest struct {
	Roles []user.Role `json:"roles"`
}

type passwordRequest struct {
	Password string `json:"password"`
	// Generate makes a one-time password instead; it is returned once.
	Generate bool `json:"generate"`
	// MustResetOnLogin defaults to true: the user replaces an
	// administrator's password at their next sign-in.
	MustResetOnLogin *bool `json:"must_change_password"`
}

// createResponse is the user plus, when one was generated, the one-time
// password. It is returned exactly once and never stored in clear.
type createResponse struct {
	*user.User
	InitialPassword string `json:"initial_password,omitempty"`
}

func (h *AdminHandler) list(w http.ResponseWriter, r *http.Request) {
	limit, cursor := httpx.Paging(r, 50, 500)
	users, next, err := h.Users.List(r.Context(), cursor, limit)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
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
		httpx.BadRequest(w, r, err.Error())
		return
	}
	if len(req.Roles) == 0 {
		httpx.BadRequest(w, r, "at least one role is required")
		return
	}
	u := &user.User{
		Username:    strings.TrimSpace(req.Username),
		DisplayName: strings.TrimSpace(req.DisplayName),
		Email:       req.Email,
		Roles:       req.Roles,
	}
	// A local account gets a password: the administrator's, or a generated
	// one-time password returned once. Either way the user replaces it at
	// their first sign-in unless the request says otherwise (QA finding
	// R25). An account that will sign in through an identity provider is
	// created with password_less: true and no password, so that its
	// provider adopts it at the first sign-in.
	initial, source := "", "none"
	switch {
	case req.Password != "":
		if err := user.CheckPasswordPolicy(req.Password); err != nil {
			httpx.BadRequest(w, r, err.Error())
			return
		}
		initial, source = req.Password, "set"
	case !req.PasswordLess:
		pw, err := user.GeneratePassword()
		if err != nil {
			httpx.Internal(w, r, h.Log, err)
			return
		}
		initial, source = pw, "generated"
	}
	if initial != "" {
		hash, err := user.HashPassword(initial)
		if err != nil {
			httpx.Internal(w, r, h.Log, err)
			return
		}
		u.PasswordHash = hash
		u.MustResetOnLogin = req.MustResetOnLogin == nil || *req.MustResetOnLogin
	}
	if err := h.Users.CreateInGroups(r.Context(), u, req.GroupIDs); err != nil {
		h.fail(w, r, err)
		return
	}
	details := map[string]any{"username": u.Username, "roles": u.Roles, "has_password": u.PasswordHash != "", "initial_password": source, "must_change_password": u.MustResetOnLogin}
	if len(req.GroupIDs) > 0 {
		details["group_ids"] = req.GroupIDs
	}
	if granted := privileged(u.Roles); len(granted) > 0 {
		details["roles_granted"] = granted
	}
	h.record(r, audit.UserCreate, u.ID, audit.Success, details)
	out := createResponse{User: u}
	if source == "generated" {
		out.InitialPassword = initial
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (h *AdminHandler) get(w http.ResponseWriter, r *http.Request) {
	u, err := h.Users.GetByID(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *AdminHandler) update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req updateRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	existing, err := h.Users.GetByID(r.Context(), id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = existing.DisplayName
	}
	if req.Status == "" {
		req.Status = existing.Status
	}
	email := existing.Email
	if req.Email != nil {
		email = *req.Email
	}
	if req.Status != user.StatusActive && h.isSelf(r, id) {
		httpx.WriteError(w, r, http.StatusConflict, "self", "you cannot disable or lock your own account")
		return
	}
	// An account its provider took away (the sync or SCIM disabled and
	// marked it) stays the provider's while the provider still lists or
	// pushes its people: it is enabled again when they are back (ADR 0035,
	// amended 2026-10-31). Enabling it by hand made an active account of a
	// person the directory no longer has. A name or email edit stands.
	if req.Status != existing.Status && existing.DirectoryRemovedAt != nil && existing.IdPID != "" && h.ProviderHolds != nil {
		name, holds, err := h.ProviderHolds(r.Context(), existing.IdPID)
		if err != nil {
			httpx.Internal(w, r, h.Log, err)
			return
		}
		if holds {
			httpx.WriteError(w, r, http.StatusConflict, "left_provider", name+" no longer has this person; the account is enabled again when it does")
			return
		}
	}
	if err := h.Users.Update(r.Context(), id, req.DisplayName, email, req.Status); err != nil {
		h.fail(w, r, err)
		return
	}
	if req.Status != user.StatusActive && existing.Status == user.StatusActive {
		if _, err := h.Sessions.RevokeAllForUser(r.Context(), id); err != nil {
			h.Log.Error("revoke sessions after status change", "user_id", id, "err", err)
		}
	}
	details := map[string]any{
		"display_name": req.DisplayName, "email": email, "status": req.Status, "previous_status": existing.Status,
	}
	if req.Status == user.StatusDisabled || req.Status == user.StatusLocked {
		h.endLive(id, details)
	}
	h.record(r, audit.UserUpdate, id, audit.Success, details)
	u, err := h.Users.GetByID(r.Context(), id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *AdminHandler) setRoles(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req rolesRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	if len(req.Roles) == 0 {
		httpx.BadRequest(w, r, "at least one role is required")
		return
	}
	before, err := h.Users.GetByID(r.Context(), id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.Users.SetRoles(r.Context(), id, req.Roles); err != nil {
		h.fail(w, r, err)
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
	if !sameRoles(before.Roles, req.Roles) {
		h.endLive(id, details)
	}
	h.record(r, audit.UserRolesUpdate, id, audit.Success, details)
	u, err := h.Users.GetByID(r.Context(), id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *AdminHandler) setPassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req passwordRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	pw, source := req.Password, "set"
	if req.Generate {
		var err error
		if pw, err = user.GeneratePassword(); err != nil {
			httpx.Internal(w, r, h.Log, err)
			return
		}
		source = "generated"
	}
	if err := user.CheckPasswordPolicy(pw); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	hash, err := user.HashPassword(pw)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	mustChange := req.MustResetOnLogin == nil || *req.MustResetOnLogin
	if err := h.Users.SetPasswordHash(r.Context(), id, hash, mustChange); err != nil {
		h.fail(w, r, err)
		return
	}
	n, err := h.Sessions.RevokeAllForUser(r.Context(), id)
	if err != nil {
		h.Log.Error("revoke sessions after password reset", "user_id", id, "err", err)
	}
	details := map[string]any{"sessions_revoked": n, "password": source, "must_change_password": mustChange}
	h.endLive(id, details)
	h.record(r, audit.UserPasswordReset, id, audit.Success, details)
	out := map[string]any{"status": "ok", "sessions_revoked": n, "must_change_password": mustChange}
	if req.Generate {
		out["initial_password"] = pw
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *AdminHandler) revokeSessions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := h.Users.GetByID(r.Context(), id); err != nil {
		h.fail(w, r, err)
		return
	}
	n, err := h.Sessions.RevokeAllForUser(r.Context(), id)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	details := map[string]any{"sessions_revoked": n}
	h.endLive(id, details)
	h.record(r, audit.UserSessionsRevoke, id, audit.Success, details)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok", "sessions_revoked": n})
}

func (h *AdminHandler) resetMFA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := h.Users.GetByID(r.Context(), id); err != nil {
		h.fail(w, r, err)
		return
	}
	// A session that passed MFA with the old authenticator should not outlive
	// it, in the console or on a target.
	n, err := auth.ResetMFA(r.Context(), h.TOTP, h.Sessions, id)
	details := map[string]any{"sessions_revoked": n}
	switch {
	case errors.Is(err, auth.ErrSignOutAfterReset):
		h.Log.Error("revoke sessions after mfa reset", "user_id", id, "err", err)
		details["sign_out_failed"] = true
	case err != nil:
		httpx.Internal(w, r, h.Log, err)
		return
	}
	h.endLive(id, details)
	h.record(r, audit.UserMFAReset, id, audit.Success, details)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok", "sessions_revoked": n})
}

func (h *AdminHandler) del(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if h.isSelf(r, id) {
		httpx.WriteError(w, r, http.StatusConflict, "self", "you cannot delete your own account")
		return
	}
	u, err := h.Users.GetByID(r.Context(), id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// Refused before anything is revoked or ended: an account the record
	// keeps is disabled, not deleted.
	if has, err := h.Users.HasHistory(r.Context(), id); err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	} else if has {
		h.fail(w, r, user.ErrHasHistory)
		return
	}
	if _, err := h.Sessions.RevokeAllForUser(r.Context(), id); err != nil {
		h.Log.Error("revoke sessions before delete", "user_id", id, "err", err)
	}
	details := map[string]any{"username": u.Username, "roles": u.Roles}
	h.endLive(id, details)
	if err := h.Users.Delete(r.Context(), id); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.UserDelete, id, audit.Success, details)
	w.WriteHeader(http.StatusNoContent)
}

// ---- helpers

// endLive ends the user's live sessions through the gateway (ADR 0013) and
// records how many in details. Without a gateway it does nothing.
func (h *AdminHandler) endLive(userID string, details map[string]any) {
	if h.Revoker == nil {
		return
	}
	details["live_sessions_ended"] = h.Revoker.UserRevoked(userID)
}

// sameRoles reports whether two role lists hold the same roles, in any order.
func sameRoles(a, b []user.Role) bool {
	set := func(roles []user.Role) map[user.Role]bool {
		m := map[user.Role]bool{}
		for _, role := range roles {
			m[role] = true
		}
		return m
	}
	sa, sb := set(a), set(b)
	if len(sa) != len(sb) {
		return false
	}
	for role := range sa {
		if !sb[role] {
			return false
		}
	}
	return true
}

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
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(action, "user", objectID, outcome, details))
}

func (h *AdminHandler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, user.ErrNotFound):
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "no such user")
	case errors.Is(err, user.ErrDuplicate):
		httpx.WriteError(w, r, http.StatusConflict, "conflict", "username or email already exists")
	case errors.Is(err, user.ErrLastAdmin):
		httpx.WriteError(w, r, http.StatusConflict, "last_admin", "this is the last active admin")
	case errors.Is(err, user.ErrHasHistory):
		httpx.WriteError(w, r, http.StatusConflict, "has_history", "this account has sessions on record, which keep it; disable it instead of deleting it")
	case errors.Is(err, user.ErrUnknownGroup):
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, "invalid_group", err.Error())
	case errors.Is(err, user.ErrInvalidRole), errors.Is(err, user.ErrUsernameShape),
		errors.Is(err, user.ErrInvalidInput), errors.Is(err, user.ErrWeakPassword):
		httpx.BadRequest(w, r, err.Error())
	default:
		httpx.Internal(w, r, h.Log, err)
	}
}
