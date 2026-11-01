// SPDX-License-Identifier: Apache-2.0

package asg

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"maps"
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
	// Providers builds a cloud client for a group, for the access test. It
	// must not cache (AWSFresh): the test is whether the role can be assumed
	// now. Nil disables the test endpoints.
	Providers ProviderFactory
	// Policies, Requests and Live are what deleting a group reaches (ADR
	// 0036, amended 2026-10-30): the grants that name it, its open access
	// requests, the live sessions on its instances. Nil skips that part.
	Policies *policy.Repo
	Requests target.Requests
	Live     *gateway.Registry
	// Revoker ends the live sessions on the group's instances when the
	// group is disabled (ADR 0013); nil leaves them to their own limits.
	Revoker gateway.Revoker
	Audit   *audit.Log
	Log     *slog.Logger
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
	mux.Handle("GET /api/v1/autoscaling-groups/{id}/usage", admin(http.HandlerFunc(h.usage)))
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
		httpx.Internal(w, r, h.Log, err)
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
		httpx.BadRequest(w, r, err.Error())
		return
	}
	if err := h.userSupplied(r, body.Credentials); err != nil {
		h.fail(w, r, err)
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
	h.record(r, audit.ASGCreate, g, audit.Success, nil)
	httpx.WriteJSON(w, http.StatusCreated, g)
}

// userSupplied turns the "user supplied" choice in a write's credentials into
// the shared row that stands for it, as binding one protocol does: the
// console's group form offers the same three choices as the group's drawer.
func (h *AdminHandler) userSupplied(r *http.Request, creds map[target.Protocol]string) error {
	for proto, id := range creds {
		if id != credential.UserSuppliedSentinel || h.Vault == nil {
			continue
		}
		p, _ := auth.FromContext(r.Context())
		cid, err := h.Vault.EnsureUserSupplied(r.Context(), p.User.ID)
		if err != nil {
			return err
		}
		creds[proto] = cid
	}
	return nil
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
		httpx.BadRequest(w, r, err.Error())
		return
	}
	if err := h.userSupplied(r, body.Credentials); err != nil {
		h.fail(w, r, err)
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
	details := map[string]any{"before": before}
	// A group taken out of service keeps no session on any of its
	// instances; the registry keys them by instance row id.
	if h.Revoker != nil && before["status"] == "active" && g.Status == "disabled" {
		ended := 0
		instances, err := h.Repo.Instances(r.Context(), g.ID, false)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		for _, in := range instances {
			ended += h.Revoker.TargetDisabled(in.ID)
		}
		details["live_sessions_ended"] = ended
	}
	h.record(r, audit.ASGUpdate, g, audit.Success, details)
	if rotated {
		h.record(r, audit.ASGExternalIDRotate, g, audit.Success, nil)
	}
	httpx.WriteJSON(w, http.StatusOK, g)
}

func (h *AdminHandler) delete(w http.ResponseWriter, r *http.Request) {
	g, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	live, err := h.instanceIDs(r.Context(), g)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	var removals []policy.Removal
	var closed int64
	err = h.Repo.DeleteWith(r.Context(), g.ID, func(tx *sql.Tx) error {
		var err error
		if h.Policies != nil {
			if removals, err = h.Policies.RemoveTargetTx(r.Context(), tx, "", g.ID); err != nil {
				return err
			}
		}
		if h.Requests != nil {
			if closed, err = h.Requests.CloseForTargetTx(r.Context(), tx, "", g.ID, "autoscaling group deleted"); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	ended := target.EndSessions(h.Live, live)
	h.record(r, audit.ASGDelete, g, audit.Success, target.DeleteDetails(map[string]any{}, removals, closed, ended))
	target.RecordRemovals(r, h.Audit, removals, g.ID, g.Name)
	w.WriteHeader(http.StatusNoContent)
}

// usage answers GET /autoscaling-groups/{id}/usage: what deleting the group
// would change, for the confirmation the console shows first.
func (h *AdminHandler) usage(w http.ResponseWriter, r *http.Request) {
	g, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	live, err := h.instanceIDs(r.Context(), g)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	u, err := target.Preview(r.Context(), h.Policies, h.Requests, h.Live, "", g.ID, live)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

// instanceIDs are the ids the registry keys the group's live sessions by:
// its instances' rows.
func (h *AdminHandler) instanceIDs(ctx context.Context, g *Group) ([]string, error) {
	instances, err := h.Repo.Instances(ctx, g.ID, false)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(instances))
	for _, in := range instances {
		ids = append(ids, in.ID)
	}
	return ids, nil
}

func (h *AdminHandler) instances(w http.ResponseWriter, r *http.Request) {
	g, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	rows, err := h.Repo.Instances(r.Context(), g.ID, false)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
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
		httpx.WriteError(w, r, http.StatusNotImplemented, "sync_unavailable", "sync is not configured on this gateway")
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
	h.record(r, audit.ASGSync, g, outcome, map[string]any{"seen": sum.Seen, "healthy": sum.Healthy, "joined": sum.Joined, "left": sum.Left, "error": resp.Error})
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
		httpx.BadRequest(w, r, err.Error())
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
		httpx.WriteError(w, r, http.StatusNotImplemented, "test_unavailable", "no cloud provider is configured")
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
			httpx.BadRequest(w, r, err.Error())
			return
		}
		g = &Group{ID: "test", Name: "test", Region: strings.TrimSpace(body.Region), ExternalName: strings.TrimSpace(body.ExternalName),
			RoleARN: strings.TrimSpace(body.RoleARN), ExternalID: strings.TrimSpace(body.ExternalID), OSFamily: target.Linux}
		if g.ExternalID == "" {
			httpx.BadRequest(w, r, "external_id required: the one from the IAM preview the role was created with")
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
	h.record(r, audit.ASGTest, g, outcome, map[string]any{"role_arn": g.RoleARN, "stage": res.Stage, "group_found": res.GroupFound, "instances": res.InstanceCount})
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
	if id.Detail != "" && h.Log != nil {
		h.Log.Info("aws gateway identity not available", "reason", id.Error, "detail", id.Detail)
	}
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(audit.AWSIdentityRefresh, "gateway", "aws", audit.Success, map[string]string{"source": id.Source, "principal": id.Principal}))
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
		httpx.BadRequest(w, r, err.Error())
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
		httpx.BadRequest(w, r, "credential_id required")
		return
	}
	if err := h.Repo.SetCredential(r.Context(), g.ID, proto, body.CredentialID); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.ASGCredentialSet, g, audit.Success, map[string]any{"protocol": proto, "credential_id": body.CredentialID})
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
	h.record(r, audit.ASGCredentialUnset, g, audit.Success, map[string]any{"protocol": proto})
	w.WriteHeader(http.StatusNoContent)
}

// ---- helpers

func (h *AdminHandler) record(r *http.Request, action string, g *Group, outcome audit.Outcome, extra map[string]any) {
	details := map[string]any{"name": g.Name, "region": g.Region, "external_name": g.ExternalName}
	maps.Copy(details, extra)
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(action, "autoscaling_group", g.ID, outcome, details))
}

func (h *AdminHandler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "autoscaling group not found")
	case errors.Is(err, ErrDuplicate):
		httpx.WriteError(w, r, http.StatusConflict, "conflict", "an autoscaling group with that name exists")
	case errors.Is(err, ErrInvalidInput):
		httpx.BadRequest(w, r, err.Error())
	default:
		httpx.Internal(w, r, h.Log, err)
	}
}
