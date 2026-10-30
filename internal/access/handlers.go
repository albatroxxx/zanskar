// SPDX-License-Identifier: Apache-2.0

package access

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/asg"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Handler serves the access-request lifecycle: users request and view their own
// access; admins approve, deny and revoke (ADR 0018).
type Handler struct {
	Requests *Repo
	Policies *policy.Repo
	Targets  *target.Repo
	// ASGs finds the autoscaling group a request names; nil refuses such
	// requests as not found.
	ASGs *asg.Repo
	// Revoker ends the live sessions a revoked grant admitted (ADR 0013,
	// ADR 0018); nil leaves them to their own limits.
	Revoker gateway.Revoker
	Audit   *audit.Log
	Log     *slog.Logger
}

// Register mounts the routes. Creating and viewing one's own requests needs an
// account that may connect (user or admin; auditor-only accounts are
// review-only); approving, denying and revoking need the admin role.
func (h *Handler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("POST /api/v1/me/access-requests", auth.RequireConnect(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/v1/me/access-requests", auth.RequireConnect(http.HandlerFunc(h.myList)))
	mux.Handle("GET /api/v1/me/access", auth.RequireConnect(http.HandlerFunc(h.myActive)))
	mux.Handle("GET /api/v1/access-requests", admin(http.HandlerFunc(h.adminList)))
	mux.Handle("POST /api/v1/access-requests/{id}/approve", admin(http.HandlerFunc(h.approve)))
	mux.Handle("POST /api/v1/access-requests/{id}/deny", admin(http.HandlerFunc(h.deny)))
	mux.Handle("POST /api/v1/access-requests/{id}/revoke", admin(http.HandlerFunc(h.revoke)))
}

type createInput struct {
	// Exactly one of TargetID and ASGID names what access is asked for.
	TargetID string `json:"target_id"`
	ASGID    string `json:"asg_id"`
	Protocol string `json:"protocol"`
	Reason   string `json:"reason"`
	Minutes  int    `json:"minutes"`
	// ExtendsRequestID asks to extend the caller's active grant of that id;
	// the new grant, once approved, runs on from the old one's expiry.
	ExtendsRequestID string `json:"extends_request_id"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in createInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	pr, _ := auth.FromContext(r.Context())
	in.Reason = strings.TrimSpace(in.Reason)
	switch {
	case (in.TargetID == "") == (in.ASGID == "") || in.Protocol == "":
		httpx.BadRequest(w, r, "protocol and exactly one of target_id and asg_id are required")
		return
	case in.Reason == "":
		httpx.BadRequest(w, r, "a reason is required")
		return
	case in.Minutes < 1:
		httpx.BadRequest(w, r, "minutes must be at least 1")
		return
	}

	ref, ok := h.subject(w, r, in)
	if !ok {
		return
	}
	pols, err := h.Policies.ForUser(r.Context(), pr.User.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// Eligibility: an approval grant of the caller's enabled policies must
	// cover this target or group and protocol. Standing access is not
	// requested here; a user who already has it connects directly.
	elig, found := eligible(pols, ref, in.Protocol)
	if !found {
		httpx.WriteError(w, r, http.StatusForbidden, "not_eligible",
			"no approval-gated policy makes you eligible for this target and protocol")
		return
	}
	most := elig.maxMinutes
	if in.Minutes > most {
		httpx.WriteError(w, r, http.StatusBadRequest, "duration_too_long",
			fmt.Sprintf("requested duration exceeds the policy maximum of %d minutes", most))
		return
	}
	// One open request per (user, target or group, protocol): a second pending one
	// would only put the same decision in front of the approver twice, and a
	// request while a grant is active is an extension or nothing.
	now := time.Now().UTC()
	open, err := h.Requests.Open(r.Context(), pr.User.ID, ref.ID, ref.ASGID, in.Protocol, now)
	if err != nil && !errors.Is(err, ErrNotFound) {
		h.fail(w, r, err)
		return
	}
	switch {
	case open != nil && open.Status == StatusPending:
		httpx.WriteError(w, r, http.StatusConflict, "duplicate_request",
			"you already have a pending request for this target and protocol; wait for the decision")
		return
	case open != nil && in.ExtendsRequestID == "":
		httpx.WriteError(w, r, http.StatusConflict, "already_granted",
			fmt.Sprintf("you already hold access to this target until %s; extend that grant instead", open.ExpiresAt.UTC().Format(time.RFC3339)))
		return
	case in.ExtendsRequestID != "" && (open == nil || open.ID != in.ExtendsRequestID):
		httpx.WriteError(w, r, http.StatusConflict, "not_extendable",
			"that grant is not active for this target and protocol; request access afresh")
		return
	}

	req := &Request{UserID: pr.User.ID, PolicyID: elig.policy.ID, GrantID: elig.grant.ID, TargetID: ref.ID, ASGID: ref.ASGID,
		Protocol: in.Protocol, Reason: in.Reason, RequestedMinutes: in.Minutes, ExtendsRequestID: in.ExtendsRequestID}
	if err := h.Requests.Create(r.Context(), req); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.AccessRequestCreate, req, map[string]any{"extends_request_id": req.ExtendsRequestID})
	httpx.WriteJSON(w, http.StatusCreated, req)
}

// subject finds the host or autoscaling group a request names, as the
// reference its eligibility is judged on. When ok is false it has answered.
func (h *Handler) subject(w http.ResponseWriter, r *http.Request, in createInput) (ref policy.TargetRef, ok bool) {
	if in.TargetID != "" {
		tgt, err := h.Targets.Get(r.Context(), in.TargetID)
		if errors.Is(err, target.ErrNotFound) {
			httpx.WriteError(w, r, http.StatusNotFound, "not_found", "target not found")
			return ref, false
		}
		if err != nil {
			h.fail(w, r, err)
			return ref, false
		}
		return policy.TargetRef{Kind: tgt.Kind(), ID: tgt.ID, Tags: tgt.Tags}, true
	}
	if h.ASGs == nil {
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "autoscaling group not found")
		return ref, false
	}
	g, err := h.ASGs.Get(r.Context(), in.ASGID)
	if errors.Is(err, asg.ErrNotFound) {
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "autoscaling group not found")
		return ref, false
	}
	if err != nil {
		h.fail(w, r, err)
		return ref, false
	}
	return policy.TargetRef{Kind: protocol.KindAutoscaling, ASGID: g.ID, Tags: g.Tags}, true
}

// eligibility is what admits a request: an approval grant of the caller's
// enabled policies covering the target or group and protocol. When several
// do, the cap is the shortest of their maximums (a grant with none counts as
// DefaultMaxGrantMinutes), and the grant that sets it is the one recorded;
// ties go to the policy first by name, then the grant first in it.
type eligibility struct {
	policy     *policy.Policy
	grant      *policy.Grant
	maxMinutes int
}

func eligible(pols []*policy.Policy, ref policy.TargetRef, proto string) (eligibility, bool) {
	var best eligibility
	found := false
	for _, p := range pols {
		if !p.Enabled {
			continue
		}
		for i := range p.Grants {
			g := &p.Grants[i]
			if g.Access != policy.AccessApproval || !g.Covers(ref, proto) {
				continue
			}
			most := DefaultMaxGrantMinutes
			if g.MaxSessionMinutes != nil && *g.MaxSessionMinutes > 0 {
				most = *g.MaxSessionMinutes
			}
			if !found || most < best.maxMinutes {
				best, found = eligibility{policy: p, grant: g, maxMinutes: most}, true
			}
		}
	}
	return best, found
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
		httpx.BadRequest(w, r, "unknown status filter")
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
		httpx.WriteError(w, r, http.StatusConflict, "conflict", "request is not pending")
		return
	}
	d := h.decision(r)
	// Eligibility and the cap are decided by the policies as they stand now,
	// not as they stood when the request was made: a policy lowered, deleted
	// or moved off the requester since then bounds or refuses the grant.
	ref, ok := h.subject(w, r, createInput{TargetID: cur.TargetID, ASGID: cur.ASGID})
	if !ok {
		return
	}
	pols, err := h.Policies.ForUser(r.Context(), cur.UserID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	elig, found := eligible(pols, ref, cur.Protocol)
	if !found {
		httpx.WriteError(w, r, http.StatusConflict, "not_eligible",
			"the requester is no longer eligible: no approval-gated policy of theirs covers this target and protocol")
		return
	}
	// The approver may grant less or more than was asked, inside the policy's
	// maximum; the requested figure stays on the record beside the granted one.
	minutes := cur.RequestedMinutes
	if d.Minutes != 0 {
		if d.Minutes < 1 {
			httpx.BadRequest(w, r, "minutes must be at least 1")
			return
		}
		minutes = d.Minutes
	}
	if most := elig.maxMinutes; minutes > most {
		httpx.WriteError(w, r, http.StatusBadRequest, "duration_too_long",
			fmt.Sprintf("granted duration exceeds the policy maximum of %d minutes", most))
		return
	}
	// An extension runs on from the grant it extends while that grant is
	// still active, so back-to-back grants leave no gap; otherwise from now.
	now := time.Now().UTC()
	base := now
	if cur.ExtendsRequestID != "" {
		if prev, err := h.Requests.Get(r.Context(), cur.ExtendsRequestID); err == nil && prev.Active(now) {
			base = prev.ExpiresAt.UTC()
		}
	}
	expires := base.Add(time.Duration(minutes) * time.Minute)
	req, err := h.Requests.Decide(r.Context(), cur.ID, pr.User.ID, StatusApproved, d.Note, &expires, minutes)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.AccessRequestApprove, req, map[string]any{"expires_at": req.ExpiresAt, "approved_minutes": minutes, "extends_request_id": req.ExtendsRequestID})
	httpx.WriteJSON(w, http.StatusOK, req)
}

func (h *Handler) deny(w http.ResponseWriter, r *http.Request) {
	pr, _ := auth.FromContext(r.Context())
	req, err := h.Requests.Decide(r.Context(), r.PathValue("id"), pr.User.ID, StatusDenied, h.note(w, r), nil, 0)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.AccessRequestDeny, req, nil)
	httpx.WriteJSON(w, http.StatusOK, req)
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	req, err := h.Requests.Revoke(r.Context(), r.PathValue("id"), h.note(w, r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// Revoke means stop now: the sessions the grant admitted end with it,
	// unless standing access still covers them (ADR 0013).
	more := map[string]any{}
	if h.Revoker != nil {
		more["live_sessions_ended"] = h.Revoker.GrantRevoked(r.Context(), req.UserID, req.TargetID, req.ASGID, req.Protocol)
	}
	h.record(r, audit.AccessRequestRevoke, req, more)
	httpx.WriteJSON(w, http.StatusOK, req)
}

// decisionInput is the optional body of approve, deny and revoke.
type decisionInput struct {
	Note string `json:"note"`
	// Minutes overrides the requested duration on approve; zero keeps it.
	Minutes int `json:"minutes"`
}

// decision reads the optional decision body; an absent or malformed body
// counts as empty.
func (h *Handler) decision(r *http.Request) decisionInput {
	var body decisionInput
	if r.ContentLength == 0 {
		return body
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return decisionInput{}
	}
	body.Note = strings.TrimSpace(body.Note)
	return body
}

// note reads an optional {"note": "..."} body; absent body is fine.
func (h *Handler) note(_ http.ResponseWriter, r *http.Request) string {
	return h.decision(r).Note
}

func (h *Handler) record(r *http.Request, action string, req *Request, extra map[string]any) {
	details := map[string]any{"target_id": req.TargetID, "asg_id": req.ASGID, "protocol": req.Protocol,
		"requested_minutes": req.RequestedMinutes, "status": req.Status}
	for k, v := range extra {
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		details[k] = v
	}
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(action, "access_request", req.ID, audit.Success, details))
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "access request not found")
	case errors.Is(err, ErrState):
		httpx.WriteError(w, r, http.StatusConflict, "conflict", "request is not in a state for that action")
	case errors.Is(err, ErrDuplicate):
		httpx.WriteError(w, r, http.StatusConflict, "duplicate_request", err.Error())
	case errors.Is(err, ErrInvalid):
		httpx.BadRequest(w, r, err.Error())
	default:
		httpx.Internal(w, r, h.Log, err)
	}
}
