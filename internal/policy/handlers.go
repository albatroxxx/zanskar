// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strconv"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Inventory answers what the ids a grant names are, so a grant that names a
// target of another kind, or one that does not exist, is refused when it is
// written rather than granting nothing in silence.
type Inventory interface {
	// TargetKind returns the kind of a live target, or ok false.
	TargetKind(ctx context.Context, id string) (kind string, ok bool, err error)
	// GroupExists reports whether a live autoscaling group has this id.
	GroupExists(ctx context.Context, id string) (bool, error)
}

// AdminHandler serves /api/v1/access-policies for admins.
type AdminHandler struct {
	Repo *Repo
	// Users lets create and update refuse a review-only user subject; nil
	// skips the check (the connect routes refuse such accounts regardless).
	Users *user.Repo
	// Inventory checks the ids a grant names; nil skips the check.
	Inventory Inventory
	// Revoker re-checks the live sessions of the people a change touches;
	// nil leaves them to their own limits.
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
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Enabled     *bool        `json:"enabled"`
	Subjects    []Subject    `json:"subjects"`
	Grants      []grantInput `json:"grants"`
}

// grantInput is a grant as written: a switch left out takes its default
// (an authenticator required, clipboard and file transfer off, 15 minutes
// idle, standing access, the target's own sign-in).
type grantInput struct {
	ID                 string        `json:"id"`
	Kind               string        `json:"kind"`
	Targets            []GrantTarget `json:"targets"`
	Tags               *TagMatch     `json:"tags"`
	Access             string        `json:"access"`
	SignIn             string        `json:"sign_in"`
	RequireMFA         *bool         `json:"require_mfa"`
	AllowClipboard     bool          `json:"allow_clipboard"`
	AllowFileTransfer  bool          `json:"allow_file_transfer"`
	AllowDevTools      bool          `json:"allow_devtools"`
	IdleTimeoutMinutes int           `json:"idle_timeout_minutes"`
	MaxSessionMinutes  *int          `json:"max_session_minutes"`
	TimeWindows        []TimeWindow  `json:"time_windows"`
	RetentionDays      *int          `json:"retention_days"`
}

func (in *input) apply(p *Policy) {
	p.Name, p.Description, p.Subjects = in.Name, in.Description, in.Subjects
	p.Enabled = in.Enabled == nil || *in.Enabled
	if p.Subjects == nil {
		p.Subjects = []Subject{}
	}
	p.Grants = make([]Grant, 0, len(in.Grants))
	for _, g := range in.Grants {
		p.Grants = append(p.Grants, Grant{
			ID: g.ID, Kind: g.Kind, Targets: g.Targets, Tags: g.Tags, Access: g.Access, SignIn: g.SignIn,
			RequireMFA: g.RequireMFA == nil || *g.RequireMFA, AllowClipboard: g.AllowClipboard, AllowFileTransfer: g.AllowFileTransfer,
			AllowDevTools: g.AllowDevTools, IdleTimeoutMinutes: g.IdleTimeoutMinutes, MaxSessionMinutes: g.MaxSessionMinutes, TimeWindows: g.TimeWindows, RetentionDays: g.RetentionDays,
		})
	}
}

// legacyFields are the fields of a policy before ADR 0036. A body carrying
// any is refused by name rather than read in part: a client that wrote the
// old shape would otherwise drop every other subject and grant in silence.
var legacyFields = []string{
	"group_id", "user_id", "target_selector", "protocols", "rules", "time_windows", "max_session_minutes",
	"idle_timeout_minutes", "retention_days", "allow_clipboard", "allow_file_transfer", "require_mfa", "require_approval",
}

// decode reads the body, refusing the legacy shape with its own code.
func decode(w http.ResponseWriter, r *http.Request, in *input) bool {
	var raw map[string]json.RawMessage
	if err := httpx.DecodeJSON(r, &raw); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return false
	}
	for _, f := range legacyFields {
		if _, ok := raw[f]; ok {
			httpx.WriteError(w, r, http.StatusBadRequest, "legacy_policy_shape",
				"the policy shape changed in 1.8 (ADR 0036): "+f+" is gone; send subjects and grants")
			return false
		}
	}
	body, _ := json.Marshal(raw)
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(in); err != nil {
		httpx.BadRequest(w, r, "malformed JSON body: "+err.Error())
		return false
	}
	return true
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
	if !decode(w, r, &in) {
		return
	}
	pr, _ := auth.FromContext(r.Context())
	p := &Policy{CreatedBy: pr.User.ID}
	in.apply(p)
	if len(p.Subjects) == 0 {
		httpx.BadRequest(w, r, "a policy needs at least one group or user")
		return
	}
	for i, g := range p.Grants {
		if g.ID != "" {
			httpx.WriteError(w, r, http.StatusUnprocessableEntity, "unknown_grant", "grant "+itoa(i+1)+": a new policy's grants carry no id")
			return
		}
	}
	if !h.checkWrite(w, r, p) {
		return
	}
	if err := h.Repo.Create(r.Context(), p); err != nil {
		h.fail(w, r, err)
		return
	}
	// A new grant never loosens a term of access someone already holds, but
	// it can tighten one (its clipboard off where theirs was on).
	more := map[string]any{}
	if n, ok := h.recheck(r.Context(), p.Subjects); ok {
		more["live_sessions_ended"] = n
	}
	h.record(r, audit.PolicyCreate, p, more)
	httpx.WriteJSON(w, http.StatusCreated, p)
}

func (h *AdminHandler) update(w http.ResponseWriter, r *http.Request) {
	var in input
	if !decode(w, r, &in) {
		return
	}
	old, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	p := &Policy{ID: old.ID, CreatedBy: old.CreatedBy, CreatedAt: old.CreatedAt}
	in.apply(p)
	known := map[string]bool{}
	for _, g := range old.Grants {
		known[g.ID] = true
	}
	for i, g := range p.Grants {
		if g.ID != "" && !known[g.ID] {
			httpx.WriteError(w, r, http.StatusUnprocessableEntity, "unknown_grant", "grant "+itoa(i+1)+": id "+g.ID+" is not a grant of this policy")
			return
		}
	}
	if !h.checkWrite(w, r, p) {
		return
	}
	if err := h.Repo.Update(r.Context(), p); err != nil {
		h.fail(w, r, err)
		return
	}
	// Everyone the policy covered before or covers now: a subject removed,
	// a grant narrowed or a switch turned off ends what it took away.
	more := map[string]any{}
	if n, ok := h.recheck(r.Context(), append(slices.Clone(old.Subjects), p.Subjects...)); ok {
		more["live_sessions_ended"] = n
	}
	h.record(r, audit.PolicyUpdate, p, more)
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *AdminHandler) del(w http.ResponseWriter, r *http.Request) {
	p, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// Whom it covered is read before the delete takes the subjects with it.
	var covered []string
	if h.Revoker != nil {
		if covered, err = h.Repo.UsersCovered(r.Context(), p.Subjects); err != nil {
			h.fail(w, r, err)
			return
		}
	}
	if err := h.Repo.Delete(r.Context(), p.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	more := map[string]any{}
	if h.Revoker != nil {
		more["live_sessions_ended"] = h.Revoker.Recheck(r.Context(), covered)
	}
	h.record(r, audit.PolicyDelete, p, more)
	w.WriteHeader(http.StatusNoContent)
}

// recheck re-checks the sessions of everyone the subjects reach.
func (h *AdminHandler) recheck(ctx context.Context, subjects []Subject) (int, bool) {
	if h.Revoker == nil {
		return 0, false
	}
	users, err := h.Repo.UsersCovered(ctx, subjects)
	if err != nil {
		// The change is stored; the sessions it should end are left to their
		// own limits, and the log says so.
		log := h.Log
		if log == nil {
			log = slog.Default()
		}
		log.Error("policy change: list the users to re-check", "err", err)
		return 0, false
	}
	return h.Revoker.Recheck(ctx, users), true
}

// checkWrite applies the checks that need more than the policy itself: a
// user subject must be able to connect, and every named id must be a live
// target or group of its grant's kind. It writes the refusal itself.
func (h *AdminHandler) checkWrite(w http.ResponseWriter, r *http.Request, p *Policy) bool {
	if err := p.Validate(); err != nil {
		h.fail(w, r, err)
		return false
	}
	if h.Users != nil {
		for _, s := range p.Subjects {
			if s.Kind != SubjectUser {
				continue
			}
			u, err := h.Users.GetByID(r.Context(), s.ID)
			if errors.Is(err, user.ErrNotFound) {
				httpx.WriteError(w, r, http.StatusUnprocessableEntity, "invalid_subject", "user "+s.ID+" not found")
				return false
			}
			if err != nil {
				h.fail(w, r, err)
				return false
			}
			// An auditor-only account is review-only (ADR 0006): the connect
			// routes would refuse it, so a policy naming it could only
			// mislead the admin into thinking access was granted.
			if !u.CanConnect() {
				httpx.WriteError(w, r, http.StatusUnprocessableEntity, "review_only_subject",
					u.Username+" holds only the auditor role and is review-only; grant it the user role before naming it in a policy")
				return false
			}
		}
	}
	if h.Inventory == nil {
		return true
	}
	for i, g := range p.Grants {
		for _, t := range g.Targets {
			kind, ok, err := "", false, error(nil)
			if g.Kind == protocol.KindAutoscaling {
				kind = protocol.KindAutoscaling
				ok, err = h.Inventory.GroupExists(r.Context(), t.ID)
			} else {
				kind, ok, err = h.Inventory.TargetKind(r.Context(), t.ID)
			}
			if err != nil {
				h.fail(w, r, err)
				return false
			}
			if !ok {
				httpx.WriteError(w, r, http.StatusUnprocessableEntity, "unknown_target", "grant "+itoa(i+1)+": "+t.ID+" is not a live "+g.Kind)
				return false
			}
			if kind != g.Kind {
				httpx.WriteError(w, r, http.StatusUnprocessableEntity, "kind_mismatch", "grant "+itoa(i+1)+": "+t.ID+" is a "+kind+", not a "+g.Kind)
				return false
			}
		}
	}
	return true
}

// record audits a change to p; more adds details beyond the policy's own.
// The grants are summarised: kind, protocols, how many targets, the tag
// keys, access and sign-in. Nothing in a policy is secret.
func (h *AdminHandler) record(r *http.Request, action string, p *Policy, more map[string]any) {
	type summary struct {
		Kind      string   `json:"kind"`
		Protocols []string `json:"protocols"`
		Targets   int      `json:"targets"`
		TagKeys   []string `json:"tag_keys,omitempty"`
		Access    string   `json:"access"`
		SignIn    string   `json:"sign_in"`
	}
	grants := make([]summary, 0, len(p.Grants))
	for _, g := range p.Grants {
		s := summary{Kind: g.Kind, Targets: len(g.Targets), Access: g.Access, SignIn: g.SignIn}
		protos := map[string]bool{}
		for _, t := range g.Targets {
			for _, pr := range t.Protocols {
				protos[pr] = true
			}
		}
		if g.Tags != nil {
			for _, pr := range g.Tags.Protocols {
				protos[pr] = true
			}
			for k := range g.Tags.Match {
				s.TagKeys = append(s.TagKeys, k)
			}
			sort.Strings(s.TagKeys)
		}
		s.Protocols = servable(g.Kind, slices.Collect(maps.Keys(protos)))
		grants = append(grants, s)
	}
	details := map[string]any{"name": p.Name, "enabled": p.Enabled, "subjects": p.Subjects, "grants": grants}
	maps.Copy(details, more)
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(action, "access_policy", p.ID, audit.Success, details))
}

func (h *AdminHandler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "policy not found")
	case errors.Is(err, ErrDuplicate):
		httpx.WriteError(w, r, http.StatusConflict, "conflict", "a policy with that name exists")
	case errors.Is(err, ErrProtocolNotForKind):
		httpx.WriteError(w, r, http.StatusBadRequest, "protocol_not_for_kind", err.Error())
	case errors.Is(err, ErrUnknownSubject):
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, "invalid_subject", err.Error())
	case errors.Is(err, ErrInvalidInput):
		httpx.BadRequest(w, r, err.Error())
	default:
		httpx.Internal(w, r, h.Log, err)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
