// SPDX-License-Identifier: Apache-2.0

package access

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Handler serves the access-request lifecycle: users request and view their own
// access; admins approve, deny and revoke (ADR 0018).
type Handler struct {
	Requests *Repo
	Policies *policy.Repo
	Targets  *target.Repo
	Audit    *audit.Log
	Log      *slog.Logger
}

// Register mounts the routes. Creating and viewing one's own requests needs only
// authentication; approving, denying and revoking need the admin role.
func (h *Handler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("POST /api/v1/me/access-requests", auth.RequireAuth(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/v1/me/access-requests", auth.RequireAuth(http.HandlerFunc(h.myList)))
	mux.Handle("GET /api/v1/me/access", auth.RequireAuth(http.HandlerFunc(h.myActive)))
	mux.Handle("GET /api/v1/access-requests", admin(http.HandlerFunc(h.adminList)))
	mux.Handle("POST /api/v1/access-requests/{id}/approve", admin(http.HandlerFunc(h.approve)))
	mux.Handle("POST /api/v1/access-requests/{id}/deny", admin(http.HandlerFunc(h.deny)))
	mux.Handle("POST /api/v1/access-requests/{id}/revoke", admin(http.HandlerFunc(h.revoke)))
}

type createInput struct {
	TargetID string `json:"target_id"`
	Protocol string `json:"protocol"`
	Reason   string `json:"reason"`
	Minutes  int    `json:"minutes"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in createInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	pr, _ := auth.FromContext(r.Context())
	in.Reason = strings.TrimSpace(in.Reason)
	switch {
	case in.TargetID == "" || in.Protocol == "":
		httpx.BadRequest(w, "target_id and protocol are required")
		return
	case in.Reason == "":
		httpx.BadRequest(w, "a reason is required")
		return
	case in.Minutes < 1:
		httpx.BadRequest(w, "minutes must be at least 1")
		return
	}

	tgt, err := h.Targets.Get(r.Context(), in.TargetID)
	if err != nil {
		if errors.Is(err, target.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "target not found")
			return
		}
		h.fail(w, r, err)
		return
	}
	pols, err := h.Policies.ForUser(r.Context(), pr.User.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// Eligibility: an enabled, approval-gated policy of the caller's must cover
	// this target and protocol. Standing (non-approval) access is not requested
	// here — a user who already has it connects directly.
	elig := eligiblePolicy(pols, policy.TargetRef{ID: tgt.ID, Tags: tgt.Tags}, in.Protocol)
	if elig == nil {
		httpx.WriteError(w, http.StatusForbidden, "not_eligible",
			"no approval-gated policy makes you eligible for this target and protocol")
		return
	}
	max := DefaultMaxGrantMinutes
	if elig.MaxSessionMinutes != nil && *elig.MaxSessionMinutes > 0 {
		max = *elig.MaxSessionMinutes
	}
	if in.Minutes > max {
		httpx.WriteError(w, http.StatusBadRequest, "duration_too_long",
			fmt.Sprintf("requested duration exceeds the policy maximum of %d minutes", max))
		return
	}

	req := &Request{UserID: pr.User.ID, PolicyID: elig.ID, TargetID: tgt.ID,
		Protocol: in.Protocol, Reason: in.Reason, RequestedMinutes: in.Minutes}
	if err := h.Requests.Create(r.Context(), req); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "access.request.create", req, nil)
	httpx.WriteJSON(w, http.StatusCreated, req)
}

func (h *Handler) myList(w http.ResponseWriter, r *http.Request) {
	pr, _ := auth.FromContext(r.Context())
	list, err := h.Requests.ListByUser(r.Context(), pr.User.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[*Request]{Items: list})
}

func (h *Handler) myActive(w http.ResponseWriter, r *http.Request) {
	pr, _ := auth.FromContext(r.Context())
	list, err := h.Requests.ActiveForUser(r.Context(), pr.User.ID, time.Now().UTC())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[*Request]{Items: list})
}

func (h *Handler) adminList(w http.ResponseWriter, r *http.Request) {
	status := Status(r.URL.Query().Get("status"))
	switch status {
	case "", StatusPending, StatusApproved, StatusDenied, StatusExpired, StatusRevoked:
	default:
		httpx.BadRequest(w, "unknown status filter")
		return
	}
	list, err := h.Requests.List(r.Context(), status)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[*Request]{Items: list})
}

func (h *Handler) approve(w http.ResponseWriter, r *http.Request) {
	pr, _ := auth.FromContext(r.Context())
	cur, err := h.Requests.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if cur.Status != StatusPending {
		httpx.WriteError(w, http.StatusConflict, "conflict", "request is not pending")
		return
	}
	expires := time.Now().UTC().Add(time.Duration(cur.RequestedMinutes) * time.Minute)
	req, err := h.Requests.Decide(r.Context(), cur.ID, pr.User.ID, StatusApproved, h.note(w, r), &expires)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "access.request.approve", req, map[string]any{"expires_at": req.ExpiresAt})
	httpx.WriteJSON(w, http.StatusOK, req)
}

func (h *Handler) deny(w http.ResponseWriter, r *http.Request) {
	pr, _ := auth.FromContext(r.Context())
	req, err := h.Requests.Decide(r.Context(), r.PathValue("id"), pr.User.ID, StatusDenied, h.note(w, r), nil)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "access.request.deny", req, nil)
	httpx.WriteJSON(w, http.StatusOK, req)
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	req, err := h.Requests.Revoke(r.Context(), r.PathValue("id"), h.note(w, r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "access.request.revoke", req, nil)
	httpx.WriteJSON(w, http.StatusOK, req)
}

// note reads an optional {"note": "..."} body; absent body is fine.
func (h *Handler) note(_ http.ResponseWriter, r *http.Request) string {
	if r.ContentLength == 0 {
		return ""
	}
	var body struct {
		Note string `json:"note"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return ""
	}
	return strings.TrimSpace(body.Note)
}

func eligiblePolicy(pols []*policy.Policy, ref policy.TargetRef, protocol string) *policy.Policy {
	for _, p := range pols {
		if p.Enabled && p.RequireApproval && p.Selector.Matches(ref) && containsStr(p.Protocols, protocol) {
			return p
		}
	}
	return nil
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func (h *Handler) record(r *http.Request, action string, req *Request, extra map[string]any) {
	if h.Audit == nil {
		return
	}
	pr, _ := auth.FromContext(r.Context())
	actor := audit.Actor{UserID: pr.User.ID, IP: auth.ClientIP(r)}
	details := map[string]any{"target_id": req.TargetID, "asg_id": req.ASGID, "protocol": req.Protocol,
		"requested_minutes": req.RequestedMinutes, "status": req.Status}
	for k, v := range extra {
		details[k] = v
	}
	if _, err := h.Audit.Record(r.Context(), actor.Event(action, "access_request", req.ID, audit.Success, details)); err != nil {
		h.Log.Error("audit record failed", "action", action, "err", err)
	}
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "access request not found")
	case errors.Is(err, ErrState):
		httpx.WriteError(w, http.StatusConflict, "conflict", "request is not in a state for that action")
	case errors.Is(err, ErrInvalid):
		httpx.BadRequest(w, err.Error())
	default:
		h.Log.Error("access handler", "path", r.URL.Path, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}
