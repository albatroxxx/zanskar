// SPDX-License-Identifier: Apache-2.0

// Package scim lets an identity provider push its people to Zanskar over
// SCIM 2.0 (RFC 7643, RFC 7644), the standard Okta, Entra ID, OneLogin,
// JumpCloud, PingOne and Authentik speak (ADR 0035). Each provider has its
// own base, /api/v1/scim/<provider id>, and its own bearer token. Users
// only: groups are not provisioned.
//
// An account the provider creates is linked to the provider by username,
// with no sign-in subject yet; the first sign-in through the provider binds
// it (idp.Provisioner.Resolve). A deactivation or a deletion disables the
// account and ends its sessions, as a departure from a listed directory
// does (idp.Lifecycle); nothing is ever deleted, so the history stays.
package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/idp"
	"github.com/albatroxxx/zanskar/internal/user"
)

const (
	schemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaError = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	contentType = "application/scim+json"
	// bodyLimit bounds a request: one user, or one patch of one.
	bodyLimit = 256 << 10
	// maxCount bounds a page of users.
	maxCount = 200
)

// Handler serves the SCIM routes.
type Handler struct {
	Providers   *idp.Repo
	Provisioner *idp.Provisioner
	Lifecycle   *idp.Lifecycle
	Audit       *audit.Log
	Log         *slog.Logger
	// BaseURL is the public origin, as for OIDC; empty derives it from the
	// request.
	BaseURL string
	// Limiter slows an address that presents wrong tokens; nil makes one.
	Limiter *auth.IPLimiter
	now     func() time.Time
}

// Register mounts the routes.
func (h *Handler) Register(mux *http.ServeMux) {
	if h.Limiter == nil {
		h.Limiter = auth.NewIPLimiter(30, 10)
	}
	// Written out whole, so the API description's test sees every route.
	mux.Handle("GET /api/v1/scim/{idp}/ServiceProviderConfig", h.guard(h.serviceProviderConfig))
	mux.Handle("GET /api/v1/scim/{idp}/ResourceTypes", h.guard(h.resourceTypes))
	mux.Handle("GET /api/v1/scim/{idp}/ResourceTypes/{name}", h.guard(h.resourceType))
	mux.Handle("GET /api/v1/scim/{idp}/Schemas", h.guard(h.schemas))
	mux.Handle("GET /api/v1/scim/{idp}/Schemas/{uri}", h.guard(h.schema))
	mux.Handle("GET /api/v1/scim/{idp}/Users", h.guard(h.listUsers))
	mux.Handle("POST /api/v1/scim/{idp}/Users", h.guard(h.createUser))
	mux.Handle("GET /api/v1/scim/{idp}/Users/{id}", h.guard(h.getUser))
	mux.Handle("PUT /api/v1/scim/{idp}/Users/{id}", h.guard(h.replaceUser))
	mux.Handle("PATCH /api/v1/scim/{idp}/Users/{id}", h.guard(h.patchUser))
	mux.Handle("DELETE /api/v1/scim/{idp}/Users/{id}", h.guard(h.deleteUser))
	// Groups, any method: not provisioned (501), so a client that tries
	// them carries on with users.
	mux.Handle("/api/v1/scim/{idp}/Groups", h.guard(h.noGroups))
	mux.Handle("/api/v1/scim/{idp}/Groups/{id}", h.guard(h.noGroups))
}

func (h *Handler) clock() time.Time {
	if h.now != nil {
		return h.now()
	}
	return time.Now()
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, p *idp.Opened)

// guard admits a request that carries the provider's current token, for a
// provider that is enabled and has SCIM on. A wrong token is answered 401,
// counted against the address, and recorded the first time in a run.
func (h *Handler) guard(next handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("idp")
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		ok, err := h.Providers.CheckSCIMToken(r.Context(), id, strings.TrimSpace(token))
		if err != nil {
			h.internal(w, r, err)
			return
		}
		if !ok {
			allowed, first := h.Limiter.Take(auth.LimiterKey(auth.ClientIP(r)))
			if allowed || first {
				h.record(r, audit.Actor{IP: auth.ClientIP(r)}.Event(audit.IdPSCIM, "identity_provider", truncate(id, 64), audit.Failure,
					map[string]string{"reason": "bad_token", "method": r.Method}))
			}
			if !allowed {
				writeError(w, http.StatusTooManyRequests, "", "too many requests with a wrong token")
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="zanskar-scim"`)
			writeError(w, http.StatusUnauthorized, "", "a valid bearer token is required")
			return
		}
		p, err := h.Providers.Open(r.Context(), id)
		if err != nil {
			h.internal(w, r, err)
			return
		}
		if !p.Enabled || !p.Config.SCIM {
			writeError(w, http.StatusForbidden, "", "provisioning over SCIM is off for this provider")
			return
		}
		next(w, r, p)
	})
}

// ---- discovery (RFC 7644 section 4)

func (h *Handler) serviceProviderConfig(w http.ResponseWriter, r *http.Request, _ *idp.Opened) {
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://albatroxxx.github.io/zanskar/guide/#idp-arrive",
		"patch":            map[string]bool{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": maxCount},
		"changePassword":   map[string]bool{"supported": false},
		"sort":             map[string]bool{"supported": false},
		"etag":             map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken", "name": "Bearer token", "primary": true,
			"description": "The token the Zanskar console generated for this provider.",
		}},
		"meta": map[string]string{"resourceType": "ServiceProviderConfig", "location": h.base(r) + "/ServiceProviderConfig"},
	})
}

func (h *Handler) userResourceType(r *http.Request) map[string]any {
	return map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
		"id":      "User", "name": "User", "endpoint": "/Users", "description": "A person who signs in to Zanskar",
		"schema": schemaUser,
		"meta":   map[string]string{"resourceType": "ResourceType", "location": h.base(r) + "/ResourceTypes/User"},
	}
}

func (h *Handler) resourceTypes(w http.ResponseWriter, r *http.Request, _ *idp.Opened) {
	writeJSON(w, http.StatusOK, listResponse([]any{h.userResourceType(r)}, 1, 1))
}

func (h *Handler) resourceType(w http.ResponseWriter, r *http.Request, _ *idp.Opened) {
	if r.PathValue("name") != "User" {
		writeError(w, http.StatusNotFound, "", "only the User resource type is provisioned")
		return
	}
	writeJSON(w, http.StatusOK, h.userResourceType(r))
}

func userSchema(base string) map[string]any {
	// Every attribute is read-write: the provider owns the person.
	attr := func(name, typ string, required bool, uniqueness string, sub ...map[string]any) map[string]any {
		a := map[string]any{"name": name, "type": typ, "multiValued": false, "required": required, "caseExact": false,
			"mutability": "readWrite", "returned": "default", "uniqueness": uniqueness}
		if len(sub) > 0 {
			a["subAttributes"] = sub
		}
		return a
	}
	emails := attr("emails", "complex", false, "none",
		attr("value", "string", false, "none"), attr("type", "string", false, "none"), attr("primary", "boolean", false, "none"))
	emails["multiValued"] = true
	return map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
		"id":      schemaUser, "name": "User", "description": "A person who signs in to Zanskar",
		"attributes": []map[string]any{
			attr("userName", "string", true, "server"),
			attr("name", "complex", false, "none",
				attr("formatted", "string", false, "none"), attr("givenName", "string", false, "none"), attr("familyName", "string", false, "none")),
			attr("displayName", "string", false, "none"),
			emails,
			attr("active", "boolean", false, "none"),
			attr("externalId", "string", false, "none"),
		},
		"meta": map[string]string{"resourceType": "Schema", "location": base + "/Schemas/" + schemaUser},
	}
}

func (h *Handler) schemas(w http.ResponseWriter, r *http.Request, _ *idp.Opened) {
	writeJSON(w, http.StatusOK, listResponse([]any{userSchema(h.base(r))}, 1, 1))
}

func (h *Handler) schema(w http.ResponseWriter, r *http.Request, _ *idp.Opened) {
	if r.PathValue("uri") != schemaUser {
		writeError(w, http.StatusNotFound, "", "only the core User schema is provisioned")
		return
	}
	writeJSON(w, http.StatusOK, userSchema(h.base(r)))
}

func (h *Handler) noGroups(w http.ResponseWriter, _ *http.Request, _ *idp.Opened) {
	writeError(w, http.StatusNotImplemented, "", "groups are not provisioned; map provider groups at sign-in instead")
}

// ---- users

// filterRe is the one filter shape the common clients send to find a
// person before creating them: an attribute, eq, a quoted value.
var filterRe = regexp.MustCompile(`^\s*([A-Za-z.:]+)\s+(?i:eq)\s+("(?:[^"\\]|\\.)*")\s*$`)

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request, p *idp.Opened) {
	q := r.URL.Query()
	var f user.SCIMFilter
	if raw := q.Get("filter"); raw != "" {
		m := filterRe.FindStringSubmatch(raw)
		if m == nil {
			writeError(w, http.StatusBadRequest, "invalidFilter", `filters are "userName eq", "externalId eq" or "id eq" with a quoted value`)
			return
		}
		if err := json.Unmarshal([]byte(m[2]), &f.Value); err != nil {
			writeError(w, http.StatusBadRequest, "invalidFilter", "the filter's value is not a valid string")
			return
		}
		switch strings.ToLower(m[1]) {
		case "username":
			f.Attr = "userName"
		case "externalid":
			f.Attr = "externalId"
		case "id":
			f.Attr = "id"
		default:
			writeError(w, http.StatusBadRequest, "invalidFilter", fmt.Sprintf("cannot filter on %q", m[1]))
			return
		}
	}
	start, count := 1, 100
	if v := q.Get("startIndex"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalidValue", "startIndex must be a number")
			return
		}
		start = max(n, 1)
	}
	if v := q.Get("count"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalidValue", "count must be a number")
			return
		}
		count = min(max(n, 0), maxCount)
	}
	users, total, err := h.Provisioner.Users.ListProvisioned(r.Context(), p.ID, f, start-1, count)
	if err != nil {
		h.internal(w, r, err)
		return
	}
	items := make([]any, 0, len(users))
	for _, u := range users {
		items = append(items, h.resource(r, u))
	}
	resp := listResponse(items, total, len(items))
	resp["startIndex"] = start
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request, p *idp.Opened) {
	u, ok := h.find(w, r, p)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, h.resource(r, u))
}

// find loads the account the path names, if it is one this provider
// provisions and has not deleted; otherwise it answers 404.
func (h *Handler) find(w http.ResponseWriter, r *http.Request, p *idp.Opened) (*user.User, bool) {
	users, _, err := h.Provisioner.Users.ListProvisioned(r.Context(), p.ID, user.SCIMFilter{Attr: "id", Value: r.PathValue("id")}, 0, 1)
	if err != nil {
		h.internal(w, r, err)
		return nil, false
	}
	if len(users) == 0 {
		writeError(w, http.StatusNotFound, "", "no such user")
		return nil, false
	}
	return users[0], true
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request, p *idp.Opened) {
	in, ok := decode(w, r)
	if !ok {
		return
	}
	want, err := desiredFrom(in, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	actor := audit.Actor{IP: auth.ClientIP(r)}
	ctx := r.Context()
	users := h.Provisioner.Users
	existing, err := users.GetByUsername(ctx, want.userName)
	switch {
	case err == nil && existing.IdPID == p.ID && existing.SCIMDeletedAt != nil:
		// Deleted by this provider before, and created again (a rehire):
		// the same account, with its history, comes back.
		if err := users.SetSCIM(ctx, existing.ID, want.externalID, nil); err != nil {
			h.internal(w, r, err)
			return
		}
		existing.SCIMDeletedAt, existing.SCIMExternalID = nil, want.externalID
		if want.active == nil {
			// A create means active unless it says otherwise.
			active := true
			want.active = &active
		}
		if !h.apply(w, r, p, existing, want, actor) {
			return
		}
		h.created(w, r, existing.ID)
		return
	case err == nil && existing.IdPID == p.ID:
		writeError(w, http.StatusConflict, "uniqueness", "this provider already provisions an account with that userName")
		return
	case err == nil && existing.IdPID == "" && existing.PasswordHash == "":
		// An administrator made the account for this person, with no
		// password: it is taken over, keeping its roles (as a first sign-in
		// adopts it, ADR 0005 addendum).
		if err := users.Provision(ctx, existing.ID, p.ID, want.externalID); err != nil {
			if errors.Is(err, user.ErrDuplicate) {
				writeError(w, http.StatusConflict, "uniqueness", "an account with that userName was taken meanwhile")
				return
			}
			h.internal(w, r, err)
			return
		}
		existing.IdPID, existing.SCIMExternalID = p.ID, want.externalID
		h.record(r, actor.Event(audit.UserLink, "user", existing.ID, audit.Success,
			map[string]string{"idp": p.ID, "idp_name": p.Name, "via": "scim", "scim_external_id": want.externalID}))
		if !h.apply(w, r, p, existing, want, actor) {
			return
		}
		h.created(w, r, existing.ID)
		return
	case err == nil:
		writeError(w, http.StatusConflict, "uniqueness", "a local account, or one of another provider, has that userName")
		return
	case !errors.Is(err, user.ErrNotFound):
		h.internal(w, r, err)
		return
	}
	if !p.Config.AutoProvision {
		writeError(w, http.StatusForbidden, "", "this provider does not create accounts; turn on account creation for it, or create the account in Zanskar first")
		return
	}
	// A client may send only the userName; the account still needs a name.
	name := want.displayName()
	if name == "" {
		name = want.userName
	}
	u := &user.User{Username: want.userName, DisplayName: name, Email: want.email, Roles: p.Config.DefaultRoles,
		IdPID: p.ID, SCIMExternalID: want.externalID}
	if err := users.Create(ctx, u); err != nil {
		if errors.Is(err, user.ErrDuplicate) {
			writeError(w, http.StatusConflict, "uniqueness", "the userName or the email address is already taken")
			return
		}
		h.internal(w, r, err)
		return
	}
	d := map[string]any{"username": u.Username, "roles": u.Roles, "has_password": false, "via": "scim", "idp": p.ID, "idp_name": p.Name,
		"scim_external_id": want.externalID}
	var granted []user.Role
	for _, role := range u.Roles {
		if role != user.RoleUser {
			granted = append(granted, role)
		}
	}
	if len(granted) > 0 {
		d["roles_granted"] = granted
	}
	h.record(r, actor.Event(audit.UserCreate, "user", u.ID, audit.Success, d))
	if want.active != nil && !*want.active {
		if _, _, err := h.Lifecycle.Leave(ctx, p, u, actor, "scim", "created inactive by the provider", h.clock()); err != nil && !errors.Is(err, idp.ErrLastAdmin) {
			h.internal(w, r, err)
			return
		}
	}
	h.created(w, r, u.ID)
}

// created answers 201 with the account as it now stands.
func (h *Handler) created(w http.ResponseWriter, r *http.Request, id string) {
	u, err := h.Provisioner.Users.GetByID(r.Context(), id)
	if err != nil {
		h.internal(w, r, err)
		return
	}
	res := h.resource(r, u)
	w.Header().Set("Location", res["meta"].(map[string]string)["location"])
	writeJSON(w, http.StatusCreated, res)
}

func (h *Handler) replaceUser(w http.ResponseWriter, r *http.Request, p *idp.Opened) {
	u, ok := h.find(w, r, p)
	if !ok {
		return
	}
	in, ok := decode(w, r)
	if !ok {
		return
	}
	want, err := desiredFrom(in, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	if !h.apply(w, r, p, u, want, audit.Actor{IP: auth.ClientIP(r)}) {
		return
	}
	h.respond(w, r, u.ID, http.StatusOK)
}

func (h *Handler) patchUser(w http.ResponseWriter, r *http.Request, p *idp.Opened) {
	u, ok := h.find(w, r, p)
	if !ok {
		return
	}
	in, ok := decode(w, r)
	if !ok {
		return
	}
	want, err := patched(u, in)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	if !h.apply(w, r, p, u, want, audit.Actor{IP: auth.ClientIP(r)}) {
		return
	}
	h.respond(w, r, u.ID, http.StatusOK)
}

// deleteUser disables the account, ends its sessions and hides it from the
// provider from then on; the account and its history stay.
func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request, p *idp.Opened) {
	u, ok := h.find(w, r, p)
	if !ok {
		return
	}
	actor := audit.Actor{IP: auth.ClientIP(r)}
	if _, _, err := h.Lifecycle.Leave(r.Context(), p, u, actor, "scim", "deleted by the provider", h.clock()); err != nil {
		if errors.Is(err, idp.ErrLastAdmin) {
			writeError(w, http.StatusConflict, "mutability", "the last active administrator is never disabled")
			return
		}
		h.internal(w, r, err)
		return
	}
	now := h.clock().UTC()
	if err := h.Provisioner.Users.SetSCIM(r.Context(), u.ID, u.SCIMExternalID, &now); err != nil {
		h.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) respond(w http.ResponseWriter, r *http.Request, id string, status int) {
	u, err := h.Provisioner.Users.GetByID(r.Context(), id)
	if err != nil {
		h.internal(w, r, err)
		return
	}
	writeJSON(w, status, h.resource(r, u))
}

// apply brings an account in line with what the provider says of it, and
// reports whether it answered (an error) instead.
func (h *Handler) apply(w http.ResponseWriter, r *http.Request, p *idp.Opened, u *user.User, want desired, actor audit.Actor) bool {
	ctx := r.Context()
	users := h.Provisioner.Users
	if want.userName != "" && want.userName != u.Username {
		if err := users.Rename(ctx, u.ID, want.userName); err != nil {
			switch {
			case errors.Is(err, user.ErrDuplicate):
				writeError(w, http.StatusConflict, "uniqueness", "another account has that userName")
			case errors.Is(err, user.ErrUsernameShape):
				writeError(w, http.StatusBadRequest, "invalidValue", err.Error())
			default:
				h.internal(w, r, err)
			}
			return false
		}
		h.record(r, actor.Event(audit.UserUpdate, "user", u.ID, audit.Success, map[string]any{
			"username": want.userName, "previous_username": u.Username, "via": "scim", "idp": p.ID, "idp_name": p.Name}))
		u.Username = want.userName
	}
	name := want.displayName()
	if name == "" {
		name = u.DisplayName
	}
	email := u.Email
	if want.emailSet {
		email = want.email
	}
	if name != u.DisplayName || email != u.Email {
		if err := users.Update(ctx, u.ID, name, email, u.Status); err != nil {
			if errors.Is(err, user.ErrDuplicate) {
				writeError(w, http.StatusConflict, "uniqueness", "another account has that email address")
				return false
			}
			h.internal(w, r, err)
			return false
		}
		u.DisplayName, u.Email = name, email
	}
	if want.externalIDSet && want.externalID != u.SCIMExternalID {
		if err := users.SetSCIM(ctx, u.ID, want.externalID, u.SCIMDeletedAt); err != nil {
			h.internal(w, r, err)
			return false
		}
		u.SCIMExternalID = want.externalID
	}
	if want.active == nil {
		return true
	}
	if *want.active {
		if _, err := h.Lifecycle.Return(ctx, p, u, actor, "scim", "activated by the provider"); err != nil {
			h.internal(w, r, err)
			return false
		}
		return true
	}
	if _, _, err := h.Lifecycle.Leave(ctx, p, u, actor, "scim", "deactivated by the provider", h.clock()); err != nil {
		if errors.Is(err, idp.ErrLastAdmin) {
			writeError(w, http.StatusConflict, "mutability", "the last active administrator is never disabled")
			return false
		}
		h.internal(w, r, err)
		return false
	}
	return true
}

// resource is the account as SCIM shows it.
func (h *Handler) resource(r *http.Request, u *user.User) map[string]any {
	res := map[string]any{
		"schemas":     []string{schemaUser},
		"id":          u.ID,
		"userName":    u.Username,
		"displayName": u.DisplayName,
		"name":        map[string]string{"formatted": u.DisplayName},
		"active":      u.Status == user.StatusActive,
		"meta": map[string]string{"resourceType": "User", "created": u.CreatedAt.UTC().Format(time.RFC3339),
			"lastModified": u.UpdatedAt.UTC().Format(time.RFC3339), "location": h.base(r) + "/Users/" + u.ID},
	}
	if u.SCIMExternalID != "" {
		res["externalId"] = u.SCIMExternalID
	}
	if u.Email != "" {
		res["emails"] = []map[string]any{{"value": u.Email, "type": "work", "primary": true}}
	}
	return res
}

// ---- reading what the provider sends

// desired is what the provider says an account should be. A field it did
// not send is left as it is.
type desired struct {
	userName, given, family, formatted, display string
	email                                       string
	emailSet                                    bool
	externalID                                  string
	externalIDSet                               bool
	active                                      *bool
}

func (d desired) displayName() string {
	switch {
	case d.display != "":
		return d.display
	case d.formatted != "":
		return d.formatted
	case strings.TrimSpace(d.given+" "+d.family) != "":
		return strings.TrimSpace(d.given + " " + d.family)
	}
	return ""
}

// decode reads a JSON object with every attribute name lower-cased: SCIM
// attribute names are case-insensitive (RFC 7643 section 2.1), and clients
// differ.
func decode(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if !strings.HasPrefix(ct, contentType) && !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "", "send application/scim+json")
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, bodyLimit+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalidSyntax", "the body could not be read")
		return nil, false
	}
	if len(body) > bodyLimit {
		writeError(w, http.StatusRequestEntityTooLarge, "", "the body is too large")
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil || v == nil {
		writeError(w, http.StatusBadRequest, "invalidSyntax", "the body is not a JSON object")
		return nil, false
	}
	return lowerKeys(v).(map[string]any), true
}

func lowerKeys(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[strings.ToLower(k)] = lowerKeys(val)
		}
		return out
	case []any:
		for i := range x {
			x[i] = lowerKeys(x[i])
		}
		return x
	}
	return v
}

// desiredFrom reads a full User resource (POST, PUT), starting from base
// when there is one (a PATCH's current state).
func desiredFrom(in map[string]any, base *desired) (desired, error) {
	var d desired
	if base != nil {
		d = *base
	}
	if v, ok := in["username"]; ok {
		s, _ := v.(string)
		d.userName = strings.ToLower(strings.TrimSpace(s))
	}
	if base == nil {
		if d.userName == "" {
			return d, errors.New("userName is required")
		}
	}
	if d.userName != "" && !user.ValidUsername(d.userName) {
		return d, fmt.Errorf("userName %q cannot be a Zanskar username: letters, digits, . _ -, or an email address", d.userName)
	}
	if v, ok := in["externalid"]; ok {
		s, _ := v.(string)
		d.externalID, d.externalIDSet = strings.TrimSpace(s), true
	}
	if v, ok := in["displayname"].(string); ok {
		d.display = strings.TrimSpace(v)
	}
	if n, ok := in["name"].(map[string]any); ok {
		readName(n, &d)
	}
	if v, ok := in["emails"]; ok {
		d.email, d.emailSet = primaryEmail(v), true
	}
	if v, ok := in["active"]; ok {
		b, err := scimBool(v)
		if err != nil {
			return d, err
		}
		d.active = &b
	}
	return d, nil
}

func readName(n map[string]any, d *desired) {
	if s, ok := n["givenname"].(string); ok {
		d.given = strings.TrimSpace(s)
	}
	if s, ok := n["familyname"].(string); ok {
		d.family = strings.TrimSpace(s)
	}
	if s, ok := n["formatted"].(string); ok {
		d.formatted = strings.TrimSpace(s)
	}
}

// primaryEmail picks the primary address, else the work one, else the
// first.
func primaryEmail(v any) string {
	list, _ := v.([]any)
	pick := ""
	for i, e := range list {
		m, _ := e.(map[string]any)
		val, _ := m["value"].(string)
		val = strings.ToLower(strings.TrimSpace(val))
		if val == "" {
			continue
		}
		if p, err := scimBool(m["primary"]); err == nil && p {
			return val
		}
		if t, _ := m["type"].(string); strings.EqualFold(t, "work") || i == 0 && pick == "" {
			pick = val
		}
	}
	return pick
}

// scimBool reads a boolean as clients send it: true, or Entra ID's "True".
func scimBool(v any) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case string:
		if b, err := strconv.ParseBool(strings.TrimSpace(x)); err == nil {
			return b, nil
		}
	case nil:
		return false, nil
	}
	return false, fmt.Errorf("%v is not a boolean", v)
}

// patched applies a PatchOp (RFC 7644 section 3.5.2) to the account's
// current state. Operations name an attribute by path, or carry an object
// of attributes with no path; "op" is any case, as Entra ID capitalises it.
// Attributes Zanskar keeps nothing of (phone numbers, titles, enterprise
// extensions) are accepted and ignored, so a provider's default mapping
// does not fail.
func patched(u *user.User, in map[string]any) (desired, error) {
	// The display name starts empty: one the patch does not touch is kept
	// (apply falls back to the account's), and one it builds from name
	// parts is not hidden behind the old one.
	cur := desired{userName: u.Username, email: u.Email, externalID: u.SCIMExternalID}
	ops, ok := in["operations"].([]any)
	if !ok || len(ops) == 0 {
		return cur, errors.New("a PatchOp needs Operations")
	}
	for _, raw := range ops {
		op, _ := raw.(map[string]any)
		kind, _ := op["op"].(string)
		kind = strings.ToLower(kind)
		if kind != "add" && kind != "replace" && kind != "remove" {
			return cur, fmt.Errorf("op %q is not add, replace or remove", kind)
		}
		path, _ := op["path"].(string)
		value := op["value"]
		if path == "" {
			obj, ok := value.(map[string]any)
			if !ok {
				return cur, errors.New("an operation with no path needs an object value")
			}
			// Entra ID sends dotted names inside the object ("name.givenName").
			for k, v := range obj {
				if err := setPath(&cur, k, kind, v); err != nil {
					return cur, err
				}
			}
			continue
		}
		if err := setPath(&cur, strings.ToLower(path), kind, value); err != nil {
			return cur, err
		}
	}
	return cur, nil
}

// emailPathRe is an address addressed by a value filter, as clients write it.
var emailPathRe = regexp.MustCompile(`^emails(\[[^\]]*\])?(\.value)?$`)

func setPath(d *desired, path, kind string, v any) error {
	remove := kind == "remove"
	// text is the value a string attribute takes: empty when removed.
	text := ""
	if s, ok := v.(string); ok && !remove {
		text = strings.TrimSpace(s)
	}
	switch {
	case path == "username":
		if remove {
			return errors.New("userName cannot be removed")
		}
		name := strings.ToLower(text)
		if !user.ValidUsername(name) {
			return fmt.Errorf("userName %q cannot be a Zanskar username", name)
		}
		d.userName = name
	case path == "displayname":
		d.display = text
	case path == "name":
		if m, ok := v.(map[string]any); ok && !remove {
			readName(m, d)
		}
	case path == "name.givenname":
		d.given = text
	case path == "name.familyname":
		d.family = text
	case path == "name.formatted":
		d.formatted = text
	case path == "externalid":
		d.externalID, d.externalIDSet = text, true
	case path == "active":
		if remove {
			return errors.New("active cannot be removed")
		}
		b, err := scimBool(v)
		if err != nil {
			return err
		}
		d.active = &b
	case emailPathRe.MatchString(path):
		d.emailSet = true
		switch {
		case remove:
			d.email = ""
		case strings.HasSuffix(path, ".value"):
			d.email = strings.ToLower(text)
		default:
			list, isList := v.([]any)
			if !isList {
				list = []any{v}
			}
			d.email = primaryEmail(list)
		}
	}
	return nil
}

// ---- answers

func listResponse(items []any, total, n int) map[string]any {
	return map[string]any{"schemas": []string{schemaList}, "totalResults": total, "itemsPerPage": n, "startIndex": 1, "Resources": items}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, scimType, detail string) {
	e := map[string]any{"schemas": []string{schemaError}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		e["scimType"] = scimType
	}
	writeJSON(w, status, e)
}

func (h *Handler) internal(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.Error("scim", "route", r.Method+" "+r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "", "internal error")
}

func (h *Handler) base(r *http.Request) string {
	origin := strings.TrimRight(h.BaseURL, "/")
	if origin == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		origin = scheme + "://" + r.Host
	}
	return origin + "/api/v1/scim/" + r.PathValue("idp")
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (h *Handler) record(r *http.Request, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if _, err := h.Audit.Record(context.WithoutCancel(r.Context()), e); err != nil {
		h.Log.Error("scim: audit", "action", e.Action, "err", err)
	}
}
