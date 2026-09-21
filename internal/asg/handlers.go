// SPDX-License-Identifier: Apache-2.0

package asg

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

// AdminHandler serves /api/v1/autoscaling-groups for the admin role.
type AdminHandler struct {
	Repo *Repo
	// Sync performs one poll of a group (Syncer.SyncGroup). Nil disables
	// the sync endpoint.
	Sync func(ctx context.Context, g *Group) (Summary, error)
	// GatewayPrincipal is the ARN the gateway runs as, rendered into the
	// trust policy shown to admins. Empty leaves a placeholder.
	GatewayPrincipal string
	Audit            *audit.Log
	Log              *slog.Logger
}

// Register mounts the routes; every one requires the admin role.
func (h *AdminHandler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/autoscaling-groups", admin(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/v1/autoscaling-groups", admin(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/v1/autoscaling-groups/{id}", admin(http.HandlerFunc(h.get)))
	mux.Handle("PUT /api/v1/autoscaling-groups/{id}", admin(http.HandlerFunc(h.update)))
	mux.Handle("DELETE /api/v1/autoscaling-groups/{id}", admin(http.HandlerFunc(h.delete)))
	mux.Handle("GET /api/v1/autoscaling-groups/{id}/instances", admin(http.HandlerFunc(h.instances)))
	mux.Handle("POST /api/v1/autoscaling-groups/{id}/sync", admin(http.HandlerFunc(h.sync)))
	mux.Handle("GET /api/v1/autoscaling-groups/{id}/iam", admin(http.HandlerFunc(h.iam)))
	mux.Handle("PUT /api/v1/autoscaling-groups/{id}/credentials/{protocol}", admin(http.HandlerFunc(h.setCredential)))
	mux.Handle("DELETE /api/v1/autoscaling-groups/{id}/credentials/{protocol}", admin(http.HandlerFunc(h.unsetCredential)))
}

// Write is the request body for create and update.
type Write struct {
	Name                string                     `json:"name"`
	Region              string                     `json:"region"`
	ExternalName        string                     `json:"external_name"`
	RoleARN             string                     `json:"role_arn"`
	OSFamily            target.OSFamily            `json:"os_family"`
	Ports               map[target.Protocol]int    `json:"ports"`
	Capabilities        []target.Protocol          `json:"capabilities"`
	AddressPreference   string                     `json:"address_preference"`
	PollIntervalSeconds int                        `json:"poll_interval_seconds"`
	Tags                map[string]string          `json:"tags"`
	Status              string                     `json:"status"`
	Credentials         map[target.Protocol]string `json:"credentials"`
	// RotateExternalID generates a fresh ExternalId on update, invalidating
	// the role's current trust policy until the admin updates it.
	RotateExternalID bool `json:"rotate_external_id"`
}

func (w Write) apply(g *Group) {
	g.Name, g.Region, g.ExternalName, g.RoleARN, g.OSFamily = w.Name, w.Region, w.ExternalName, w.RoleARN, w.OSFamily
	g.Ports, g.Capabilities, g.AddressPreference, g.PollIntervalSeconds = w.Ports, w.Capabilities, w.AddressPreference, w.PollIntervalSeconds
	g.Tags, g.Status, g.Credentials = w.Tags, w.Status, w.Credentials
}

// Listed is a group with instance counts, for the list view.
type Listed struct {
	*Group
	HealthyCount  int `json:"healthy_count"`
	InstanceCount int `json:"instance_count"`
}

func (h *AdminHandler) list(w http.ResponseWriter, r *http.Request) {
	groups, err := h.Repo.List(r.Context(), false)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	out := make([]Listed, 0, len(groups))
	for _, g := range groups {
		l := Listed{Group: g}
		if rows, err := h.Repo.Instances(r.Context(), g.ID, false); err == nil {
			for _, in := range rows {
				if in.TerminatedAt != nil {
					continue
				}
				l.InstanceCount++
				if in.Healthy {
					l.HealthyCount++
				}
			}
		}
		out = append(out, l)
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[Listed]{Items: out})
}

func (h *AdminHandler) create(w http.ResponseWriter, r *http.Request) {
	var body Write
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	g := &Group{}
	body.apply(g)
	if p, ok := auth.FromContext(r.Context()); ok {
		g.CreatedBy = p.User.ID
	}
	if err := h.Repo.Create(r.Context(), g); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "asg.create", g, audit.Success, nil)
	httpx.WriteJSON(w, http.StatusCreated, g)
}

func (h *AdminHandler) get(w http.ResponseWriter, r *http.Request) {
	g, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, g)
}

func (h *AdminHandler) update(w http.ResponseWriter, r *http.Request) {
	g, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var body Write
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	before := map[string]any{"name": g.Name, "region": g.Region, "external_name": g.ExternalName, "status": g.Status}
	body.apply(g)
	rotated := false
	if body.RotateExternalID {
		g.ExternalID = NewExternalID()
		rotated = true
	}
	if err := h.Repo.Update(r.Context(), g); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "asg.update", g, audit.Success, map[string]any{"before": before})
	if rotated {
		h.record(r, "asg.external_id.rotate", g, audit.Success, nil)
	}
	httpx.WriteJSON(w, http.StatusOK, g)
}

func (h *AdminHandler) delete(w http.ResponseWriter, r *http.Request) {
	g, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.Repo.Delete(r.Context(), g.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "asg.delete", g, audit.Success, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) instances(w http.ResponseWriter, r *http.Request) {
	g, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	rows, err := h.Repo.Instances(r.Context(), g.ID, false)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	all := r.URL.Query().Get("all") == "true"
	out := make([]*Instance, 0, len(rows))
	for _, in := range rows {
		if !all && in.TerminatedAt != nil {
			continue
		}
		out = append(out, in)
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[*Instance]{Items: out})
}

// syncResponse carries the poll outcome; a cloud-side failure is reported
// in error rather than as an HTTP error so the UI can show it next to the
// last-known state.
type syncResponse struct {
	Summary Summary `json:"summary"`
	Group   *Group  `json:"group"`
	Error   string  `json:"error,omitempty"`
}

func (h *AdminHandler) sync(w http.ResponseWriter, r *http.Request) {
	g, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if h.Sync == nil {
		httpx.WriteError(w, http.StatusNotImplemented, "sync_unavailable", "sync is not configured on this gateway")
		return
	}
	sum, serr := h.Sync(r.Context(), g)
	resp := syncResponse{Summary: sum}
	outcome := audit.Success
	if serr != nil {
		resp.Error = serr.Error()
		outcome = audit.Failure
	}
	if refreshed, err := h.Repo.Get(r.Context(), g.ID); err == nil {
		resp.Group = refreshed
	} else {
		resp.Group = g
	}
	h.record(r, "asg.sync", g, outcome, map[string]any{"seen": sum.Seen, "healthy": sum.Healthy, "joined": sum.Joined, "left": sum.Left, "error": resp.Error})
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) iam(w http.ResponseWriter, r *http.Request) {
	g, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"external_id":        g.ExternalID,
		"trust_policy":       g.TrustPolicy(h.GatewayPrincipal),
		"permissions_policy": g.PermissionsPolicy(),
		"gateway_principal":  h.GatewayPrincipal,
	})
}

func (h *AdminHandler) setCredential(w http.ResponseWriter, r *http.Request) {
	g, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	proto := target.Protocol(r.PathValue("protocol"))
	var body struct {
		CredentialID string `json:"credential_id"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if body.CredentialID == "" {
		httpx.BadRequest(w, "credential_id required")
		return
	}
	if err := h.Repo.SetCredential(r.Context(), g.ID, proto, body.CredentialID); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "asg.credential.set", g, audit.Success, map[string]any{"protocol": proto, "credential_id": body.CredentialID})
	g, _ = h.Repo.Get(r.Context(), g.ID)
	httpx.WriteJSON(w, http.StatusOK, g)
}

func (h *AdminHandler) unsetCredential(w http.ResponseWriter, r *http.Request) {
	g, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	proto := target.Protocol(r.PathValue("protocol"))
	if err := h.Repo.SetCredential(r.Context(), g.ID, proto, ""); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "asg.credential.unset", g, audit.Success, map[string]any{"protocol": proto})
	w.WriteHeader(http.StatusNoContent)
}

// ---- helpers

func (h *AdminHandler) record(r *http.Request, action string, g *Group, outcome audit.Outcome, extra map[string]any) {
	if h.Audit == nil {
		return
	}
	details := map[string]any{"name": g.Name, "region": g.Region, "external_name": g.ExternalName}
	for k, v := range extra {
		details[k] = v
	}
	actor := audit.Actor{IP: auth.ClientIP(r)}
	if p, ok := auth.FromContext(r.Context()); ok {
		actor.UserID = p.User.ID
	}
	if _, err := h.Audit.Record(r.Context(), actor.Event(action, "autoscaling_group", g.ID, outcome, details)); err != nil {
		h.Log.Error("audit record failed", "action", action, "err", err)
	}
}

func (h *AdminHandler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "autoscaling group not found")
	case errors.Is(err, ErrDuplicate):
		httpx.WriteError(w, http.StatusConflict, "conflict", "an autoscaling group with that name exists")
	case errors.Is(err, ErrInvalidInput):
		httpx.BadRequest(w, err.Error())
	default:
		h.serverError(w, r, err)
	}
}

func (h *AdminHandler) serverError(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.Error("asg handler", "path", r.URL.Path, "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
}
