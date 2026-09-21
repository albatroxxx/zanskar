// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"errors"
	"net/http"
	"time"

	"github.com/albatroxxx/zanskar/internal/asg"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
)

// reachableInstance is what a user may see about a healthy instance. No
// addresses: the user never needs them and they are one less thing to leak.
type reachableInstance struct {
	ID               string     `json:"id"`
	InstanceID       string     `json:"instance_id"`
	AvailabilityZone string     `json:"availability_zone"`
	LaunchedAt       *time.Time `json:"launched_at,omitempty"`
	Healthy          bool       `json:"healthy"`
}

// myInstances lists the healthy instances of a group the caller may reach.
func (h *Handler) myInstances(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	if h.ASGs == nil {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "autoscaling is not enabled")
		return
	}
	g, err := h.ASGs.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, asg.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "group not found")
			return
		}
		h.fail(w, r, err)
		return
	}
	pols, err := h.Policies.ForUser(r.Context(), p.User.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	allowed := false
	for _, proto := range g.Capabilities {
		if policy.Evaluate(pols, policy.TargetRef{ASGID: g.ID, Tags: g.Tags}, string(proto), time.Now()).Allowed {
			allowed = true
			break
		}
	}
	if !allowed {
		httpx.WriteError(w, http.StatusForbidden, "policy_denied", "no policy grants access to this group")
		return
	}
	healthy, err := h.ASGs.Instances(r.Context(), g.ID, true)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := make([]reachableInstance, 0, len(healthy))
	for _, in := range healthy {
		out = append(out, reachableInstance{ID: in.ID, InstanceID: in.InstanceID, AvailabilityZone: in.AvailabilityZone, LaunchedAt: in.LaunchedAt, Healthy: true})
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[reachableInstance]{Items: out})
}

type failoverRequest struct {
	ASGInstanceID string          `json:"asg_instance_id"`
	Credential    *userCredential `json:"credential,omitempty"`
}

// failover issues a ticket for another healthy instance of the same group
// after a session was lost. It is never automatic: the user chooses.
func (h *Handler) failover(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	actor := audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}
	old, err := h.Sessions.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "session not found")
			return
		}
		h.fail(w, r, err)
		return
	}
	if old.UserID != p.User.ID {
		httpx.WriteError(w, http.StatusForbidden, "forbidden", "not your session")
		return
	}
	if old.ASGID == "" {
		httpx.WriteError(w, http.StatusConflict, "not_failoverable", "only autoscaling sessions can fail over")
		return
	}
	// A session that is still open may be on an instance that just became
	// unhealthy and whose bridge has not noticed yet; close it as lost.
	if old.EndedAt == nil {
		if in, err := h.ASGs.GetInstance(r.Context(), old.ASGInstanceID); err == nil && in.Healthy {
			httpx.WriteError(w, http.StatusConflict, "not_failoverable", "the current instance is still healthy")
			return
		}
		_ = h.Sessions.End(r.Context(), old.ID, session.EndTargetLost)
		if h.Registry != nil {
			h.Registry.Terminate(old.ID)
		}
	} else if old.EndReason != session.EndTargetLost {
		httpx.WriteError(w, http.StatusConflict, "not_failoverable", "the session did not end because the instance was lost")
		return
	}
	var req failoverRequest
	if r.ContentLength > 0 {
		if err := httpx.DecodeJSON(r, &req); err != nil {
			httpx.BadRequest(w, err.Error())
			return
		}
	}
	var ep *endpoint
	if req.ASGInstanceID != "" {
		ep, err = h.resolveInstance(r.Context(), req.ASGInstanceID)
		if err == nil && ep.ASGID != old.ASGID {
			err = asg.ErrNotFound
		}
	} else {
		ep, err = h.pickInstance(r.Context(), old.ASGID)
	}
	if err != nil {
		switch {
		case errors.Is(err, errNoHealthyInstances):
			httpx.WriteError(w, http.StatusConflict, "no_healthy_instances", "the autoscaling group has no healthy instances right now")
		case errors.Is(err, asg.ErrNotFound):
			httpx.WriteError(w, http.StatusNotFound, "not_found", "instance not found in this group")
		default:
			h.fail(w, r, err)
		}
		return
	}
	res, code, msg, err := h.issueTicket(r.Context(), p, auth.ClientIP(r), ep, target.Protocol(old.Protocol), req.Credential, old.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if code != "" {
		h.record(r, actor.Event("session.failover", "access_session", old.ID, audit.Failure, map[string]string{"reason": code}))
		httpx.WriteError(w, codeStatus(code), code, msg)
		return
	}
	h.record(r, actor.Event("session.failover", "access_session", old.ID, audit.Success, map[string]any{"asg_id": old.ASGID, "from_instance": old.ASGInstanceID, "to_instance": ep.ASGInstanceID}))
	httpx.WriteJSON(w, http.StatusOK, res)
}
