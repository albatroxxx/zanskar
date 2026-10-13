// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

// AdminHandler serves /api/v1/access-policies for admins.
type AdminHandler struct {
	Repo *Repo
	// Users lets create and update refuse a review-only subject; nil skips
	// the check (the connect routes refuse such accounts regardless).
	Users *user.Repo
	// Revoker ends the live sessions an update or a deletion withdraws
	// (ADR 0013); nil leaves them to their own limits.
	Revoker gateway.Revoker
	Audit   *audit.Log
	Log     *slog.Logger
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
	UserID             string       `json:"user_id"`
	Selector           Selector     `json:"target_selector"`
	Protocols          []string     `json:"protocols"`
	Rules              []Rule       `json:"rules"`
	TimeWindows        []TimeWindow `json:"time_windows"`
	MaxSessionMinutes  *int         `json:"max_session_minutes"`
	RetentionDays      *int         `json:"retention_days"`
	IdleTimeoutMinutes *int         `json:"idle_timeout_minutes"`
	AllowClipboard     *bool        `json:"allow_clipboard"`
	AllowFileTransfer  *bool        `json:"allow_file_transfer"`
	RequireMFA         *bool        `json:"require_mfa"`
	RequireApproval    *bool        `json:"require_approval"`
}

func (in *input) apply(p *Policy) {
	p.Name, p.Description, p.GroupID, p.UserID = in.Name, in.Description, in.GroupID, in.UserID
	p.Selector, p.Protocols, p.TimeWindows, p.MaxSessionMinutes = in.Selector, in.Protocols, in.TimeWindows, in.MaxSessionMinutes
	p.Rules, p.RetentionDays = in.Rules, in.RetentionDays
	p.Enabled = in.Enabled == nil || *in.Enabled
	p.IdleTimeoutMinutes = 15
	if in.IdleTimeoutMinutes != nil {
		p.IdleTimeoutMinutes = *in.IdleTimeoutMinutes
	}
	p.AllowClipboard = in.AllowClipboard != nil && *in.AllowClipboard
	p.AllowFileTransfer = in.AllowFileTransfer != nil && *in.AllowFileTransfer
	p.RequireMFA = in.RequireMFA == nil || *in.RequireMFA
	p.RequireApproval = in.RequireApproval != nil && *in.RequireApproval
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
		httpx.BadRequest(w, r, err.Error())
		return
	}
	pr, _ := auth.FromContext(r.Context())
	p := &Policy{CreatedBy: pr.User.ID}
	in.apply(p)
	if !h.subjectMayConnect(w, r, p) {
		return
	}
	if err := h.Repo.Create(r.Context(), p); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.PolicyCreate, p, nil)
	httpx.WriteJSON(w, http.StatusCreated, p)
}

func (h *AdminHandler) update(w http.ResponseWriter, r *http.Request) {
	var in input
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	p, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	in.apply(p)
	if !h.subjectMayConnect(w, r, p) {
		return
	}
	if err := h.Repo.Update(r.Context(), p); err != nil {
		h.fail(w, r, err)
		return
	}
	// Live sessions the policy admitted end if it no longer grants them.
	more := map[string]any{}
	if h.Revoker != nil {
		more["live_sessions_ended"] = h.Revoker.PolicyChanged(r.Context(), p.ID)
	}
	h.record(r, audit.PolicyUpdate, p, more)
	httpx.WriteJSON(w, http.StatusOK, p)
}

// subjectMayConnect refuses a user-scoped policy whose subject is an
// auditor-only account, writing the error itself. Such an account is
// review-only (ADR 0006): the connect routes would refuse it anyway, so a
// policy naming it could only mislead the admin into thinking access was
// granted. Group subjects are not inspected; a review-only member of a group
// is still refused at connect time. Returns true when the policy may proceed.
func (h *AdminHandler) subjectMayConnect(w http.ResponseWriter, r *http.Request, p *Policy) bool {
	if h.Users == nil || p.UserID == "" {
		return true
	}
	u, err := h.Users.GetByID(r.Context(), p.UserID)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			httpx.WriteError(w, r, http.StatusUnprocessableEntity, "invalid_subject", "user not found")
			return false
		}
		h.fail(w, r, err)
		return false
	}
	if !u.CanConnect() {
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, "review_only_subject",
			"that account holds only the auditor role and is review-only; grant it the user role before writing a policy for it")
		return false
	}
	return true
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
	more := map[string]any{}
	if h.Revoker != nil {
		more["live_sessions_ended"] = h.Revoker.PolicyDeleted(p.ID)
	}
	h.record(r, audit.PolicyDelete, p, more)
	w.WriteHeader(http.StatusNoContent)
}

// record audits a change to p; more adds details beyond the policy's own.
func (h *AdminHandler) record(r *http.Request, action string, p *Policy, more map[string]any) {
	details := map[string]any{"name": p.Name, "group_id": p.GroupID, "user_id": p.UserID, "protocols": p.Protocols, "selector": p.Selector, "enabled": p.Enabled}
	for k, v := range more {
		details[k] = v
	}
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(action, "access_policy", p.ID, audit.Success, details))
}

func (h *AdminHandler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "policy not found")
	case errors.Is(err, ErrDuplicate):
		httpx.WriteError(w, r, http.StatusConflict, "conflict", "a policy with that name exists")
	case errors.Is(err, ErrInvalidInput):
		httpx.BadRequest(w, r, err.Error())
	default:
		httpx.Internal(w, r, h.Log, err)
	}
}
