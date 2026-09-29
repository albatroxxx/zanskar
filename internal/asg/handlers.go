// SPDX-License-Identifier: Apache-2.0

package asg

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/cloud"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

// AdminHandler serves /api/v1/autoscaling-groups for the admin role.
type AdminHandler struct {
	Repo *Repo
	// Sync performs one poll of a group (Syncer.SyncGroup). Nil disables
	// the sync endpoint.
	Sync func(ctx context.Context, g *Group) (Summary, error)
	// Identity resolves the ARN the gateway runs as, rendered into the trust
	// policy shown to admins (ADR 0023). Nil means unknown: the trust policy
	// is withheld rather than rendered with a placeholder.
	Identity *cloud.GatewayIdentity
	// Providers builds a cloud client for a group, for the access test. Nil
	// disables the test endpoints.
	Providers ProviderFactory
	// Policies and Live let delete refuse a group that a policy still names
	// by id or whose instances have sessions open (ADR 0019); nil skips it.
	Policies *policy.Repo
	Live     *gateway.Registry
	Audit    *audit.Log
	Log      *slog.Logger
	// Vault resolves the user_supplied sentinel when a slot is set to
	// prompt; nil disables the sentinel.
	Vault *credential.Vault
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
	// Guided enrolment (ADR 0023): the IAM documents before a group exists,
	// an access test before and after it is saved, and the gateway's own
	// identity.
	mux.Handle("POST /api/v1/autoscaling-groups/iam-preview", admin(http.HandlerFunc(h.iamPreview)))
	mux.Handle("POST /api/v1/autoscaling-groups/test", admin(http.HandlerFunc(h.testAccess)))
	mux.Handle("POST /api/v1/autoscaling-groups/{id}/test", admin(http.HandlerFunc(h.testAccess)))
	mux.Handle("GET /api/v1/admin/aws/identity", admin(http.HandlerFunc(h.identity)))
	mux.Handle("POST /api/v1/admin/aws/identity/refresh", admin(http.HandlerFunc(h.identityRefresh)))
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
	// ExternalID, on create only, is the one an IAM preview minted, so the
	// saved group matches the role the customer already created with it.
	ExternalID string `json:"external_id,omitempty"`
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
	g := &Group{ExternalID: strings.TrimSpace(body.ExternalID)}
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
	blocked, err := h.deleteBlockedBy(r.Context(), g)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	if blocked != "" {
		h.record(r, "asg.delete", g, audit.Failure, map[string]any{"reason": "in_use"})
		httpx.WriteError(w, http.StatusConflict, "in_use", blocked)
		return
	}
	if err := h.Repo.Delete(r.Context(), g.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "asg.delete", g, audit.Success, nil)
	w.WriteHeader(http.StatusNoContent)
}

// deleteBlockedBy explains why the group cannot be retired yet: policies that
// name it by id and sessions still open on its instances (the registry keys
// those by instance row id). Empty means it may go.
func (h *AdminHandler) deleteBlockedBy(ctx context.Context, g *Group) (string, error) {
	var policies []string
	if h.Policies != nil {
		var err error
		if policies, err = h.Policies.Referencing(ctx, "", g.ID); err != nil {
			return "", err
		}
	}
	open := 0
	if h.Live != nil {
		instances, err := h.Repo.Instances(ctx, g.ID, false)
		if err != nil {
			return "", err
		}
		ids := make(map[string]bool, len(instances))
		for _, in := range instances {
			ids[in.ID] = true
		}
		for _, l := range h.Live.List() {
			if ids[l.TargetID] {
				open++
			}
		}
	}
	return target.InUseMessage("autoscaling group", policies, open), nil
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
	httpx.WriteJSON(w, http.StatusOK, h.iamDocs(r.Context(), g))
}

// previewRequest names the group the IAM documents are for, before it is
// saved. external_id is optional: absent, a new one is minted.
type previewRequest struct {
	Region       string `json:"region"`
	ExternalName string `json:"external_name"`
	ExternalID   string `json:"external_id"`
}

// iamPreview renders the IAM documents for a group that does not exist yet,
// minting the ExternalId the customer's role must carry. The client sends
// that ExternalId back on create.
func (h *AdminHandler) iamPreview(w http.ResponseWriter, r *http.Request) {
	var body previewRequest
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	g := &Group{Name: "preview", Region: strings.TrimSpace(body.Region), ExternalName: strings.TrimSpace(body.ExternalName),
		RoleARN: "arn:aws:iam::000000000000:role/preview", ExternalID: strings.TrimSpace(body.ExternalID), OSFamily: target.Linux}
	if err := g.Validate(); err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.iamDocs(r.Context(), g))
}

// AccessTest is the result of an access test (ADR 0023).
type AccessTest struct {
	OK bool `json:"ok"`
	// Stage that failed: assume (trust policy or ExternalId), describe
	// (permissions policy), group (no such group in that region); "" when OK.
	Stage         string `json:"stage,omitempty"`
	Error         string `json:"error,omitempty"`
	AssumedARN    string `json:"assumed_arn,omitempty"`
	GroupFound    bool   `json:"group_found"`
	InstanceCount int    `json:"instance_count"`
}

// testAccess assumes the role with the ExternalId and describes the group,
// for a saved group ({id}) or for one about to be saved (body). It changes
// nothing and is audited as asg.test.
func (h *AdminHandler) testAccess(w http.ResponseWriter, r *http.Request) {
	if h.Providers == nil {
		httpx.WriteError(w, http.StatusNotImplemented, "test_unavailable", "no cloud provider is configured")
		return
	}
	var g *Group
	if id := r.PathValue("id"); id != "" {
		var err error
		if g, err = h.Repo.Get(r.Context(), id); err != nil {
			h.fail(w, r, err)
			return
		}
	} else {
		var body Write
		if err := httpx.DecodeJSON(r, &body); err != nil {
			httpx.BadRequest(w, err.Error())
			return
		}
		g = &Group{ID: "test", Name: "test", Region: strings.TrimSpace(body.Region), ExternalName: strings.TrimSpace(body.ExternalName),
			RoleARN: strings.TrimSpace(body.RoleARN), ExternalID: strings.TrimSpace(body.ExternalID), OSFamily: target.Linux}
		if g.ExternalID == "" {
			httpx.BadRequest(w, "external_id required: the one from the IAM preview the role was created with")
			return
		}
		if err := g.Validate(); err != nil {
			h.fail(w, r, err)
			return
		}
	}
	res := AccessTest{}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	provider, err := h.Providers(ctx, g)
	if err != nil {
		res.Stage, res.Error = "assume", err.Error()
	} else if chk, err := provider.Check(ctx, g.ExternalName); err != nil {
		res.Stage, res.Error = "assume", err.Error()
	} else {
		res.AssumedARN, res.GroupFound, res.InstanceCount = chk.AssumedARN, chk.GroupFound, chk.InstanceCount
		switch {
		case chk.DescribeError != "":
			res.Stage, res.Error = "describe", chk.DescribeError
		case !chk.GroupFound:
			res.Stage, res.Error = "group", "the role works, but no autoscaling group named "+g.ExternalName+" exists in "+g.Region
		default:
			res.OK = true
		}
	}
	outcome := audit.Success
	if !res.OK {
		outcome = audit.Failure
	}
	h.record(r, "asg.test", g, outcome, map[string]any{"role_arn": g.RoleARN, "stage": res.Stage, "group_found": res.GroupFound, "instances": res.InstanceCount})
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *AdminHandler) identity(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.gatewayIdentity(r.Context()))
}

func (h *AdminHandler) identityRefresh(w http.ResponseWriter, r *http.Request) {
	id := cloud.Identity{Source: cloud.SourceNone}
	if h.Identity != nil {
		id = h.Identity.Refresh(r.Context())
	}
	if h.Audit != nil {
		a := audit.Actor{IP: auth.ClientIP(r)}
		if p, ok := auth.FromContext(r.Context()); ok {
			a.UserID = p.User.ID
		}
		if _, err := h.Audit.Record(r.Context(), a.Event("aws.identity.refresh", "gateway", "aws", audit.Success, map[string]string{"source": id.Source, "principal": id.Principal})); err != nil {
			h.Log.Error("audit record failed", "action", "aws.identity.refresh", "err", err)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, id)
}

func (h *AdminHandler) gatewayIdentity(ctx context.Context) cloud.Identity {
	if h.Identity == nil {
		return cloud.Identity{Source: cloud.SourceNone, CheckedAt: time.Now().UTC()}
	}
	return h.Identity.Get(ctx)
}

// IAMDocs is everything the customer needs to create the role, with the
// real gateway principal or nothing: never a placeholder (ADR 0023).
type IAMDocs struct {
	ExternalID        string `json:"external_id"`
	GatewayPrincipal  string `json:"gateway_principal,omitempty"`
	PrincipalSource   string `json:"principal_source"`
	PrincipalError    string `json:"principal_error,omitempty"`
	RoleName          string `json:"role_name"`
	TrustPolicy       string `json:"trust_policy,omitempty"`
	PermissionsPolicy string `json:"permissions_policy"`
	CLI               string `json:"cli,omitempty"`
	CloudFormation    string `json:"cloudformation,omitempty"`
}

func (h *AdminHandler) iamDocs(ctx context.Context, g *Group) IAMDocs {
	id := h.gatewayIdentity(ctx)
	docs := IAMDocs{ExternalID: g.ExternalID, GatewayPrincipal: id.Principal, PrincipalSource: id.Source, PrincipalError: id.Error,
		RoleName: g.SuggestedRoleName(), PermissionsPolicy: g.PermissionsPolicy()}
	if id.Principal == "" {
		return docs
	}
	docs.TrustPolicy = g.TrustPolicy(id.Principal)
	docs.CLI = g.RoleCLI(docs.RoleName, docs.TrustPolicy)
	docs.CloudFormation = g.RoleCloudFormation(docs.RoleName, docs.TrustPolicy)
	return docs
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
	if body.CredentialID == credential.UserSuppliedSentinel && h.Vault != nil {
		p, _ := auth.FromContext(r.Context())
		cid, err := h.Vault.EnsureUserSupplied(r.Context(), p.User.ID)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		body.CredentialID = cid
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
