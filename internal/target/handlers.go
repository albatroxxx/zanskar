// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/sshgw"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/sshca"
	"github.com/albatroxxx/zanskar/internal/user"
)

// ProbeTimeout bounds one admin-triggered probe.
const ProbeTimeout = 5 * time.Second

// AdminHandler serves /api/v1/targets for the admin role.
type AdminHandler struct {
	Repo   *Repo
	Prober *Prober
	// Policies and Live let delete refuse a target that a policy still names
	// by id or that has sessions open (ADR 0019); nil skips that check.
	Policies *policy.Repo
	Live     *gateway.Registry
	// Vault resolves the user_supplied sentinel when a slot is set to
	// prompt; nil disables the sentinel.
	Vault *credential.Vault
	Audit *audit.Log
	Log   *slog.Logger
}

// Register mounts the routes; every one requires the admin role.
func (h *AdminHandler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/targets", admin(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/v1/targets", admin(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/v1/targets/{id}", admin(http.HandlerFunc(h.get)))
	mux.Handle("PUT /api/v1/targets/{id}", admin(http.HandlerFunc(h.update)))
	mux.Handle("DELETE /api/v1/targets/{id}", admin(http.HandlerFunc(h.delete)))
	mux.Handle("POST /api/v1/targets/{id}/probe", admin(http.HandlerFunc(h.probe)))
	mux.Handle("POST /api/v1/targets/{id}/probe-certificate", admin(http.HandlerFunc(h.probeCertificate)))
	mux.Handle("POST /api/v1/targets/{id}/host-key/trust", admin(http.HandlerFunc(h.trustHostKey)))
	mux.Handle("PUT /api/v1/targets/{id}/credentials/{protocol}", admin(http.HandlerFunc(h.setCredential)))
	mux.Handle("DELETE /api/v1/targets/{id}/credentials/{protocol}", admin(http.HandlerFunc(h.unsetCredential)))
}

// Write is the request body for create and update.
type Write struct {
	Name          string              `json:"name"`
	Address       string              `json:"address"`
	Engine        string              `json:"engine"`         // database targets (ADR 0017)
	EngineVersion string              `json:"engine_version"` // database targets
	RetentionDays *int                `json:"retention_days"` // recording retention override; null defers
	DatabaseName  string              `json:"database_name"`  // database targets
	TLSMode       string              `json:"tls_mode"`       // database targets
	TLSCA         string              `json:"tls_ca"`         // database targets
	OSFamily      OSFamily            `json:"os_family"`
	Ports         map[Protocol]int    `json:"ports"`
	Capabilities  []Protocol          `json:"capabilities"`
	Tags          map[string]string   `json:"tags"`
	Status        string              `json:"status"`
	Notes         string              `json:"notes"`
	Credentials   map[Protocol]string `json:"credentials"`
}

func (w Write) apply(t *Target) {
	t.Name, t.Address, t.OSFamily = w.Name, w.Address, w.OSFamily
	t.Engine, t.EngineVersion = w.Engine, w.EngineVersion
	t.RetentionDays = w.RetentionDays
	t.DatabaseName, t.TLSMode, t.TLSCA = w.DatabaseName, w.TLSMode, w.TLSCA
	t.Ports, t.Capabilities, t.Tags = w.Ports, w.Capabilities, w.Tags
	t.Status, t.Notes, t.Credentials = w.Status, w.Notes, w.Credentials
}

func (h *AdminHandler) list(w http.ResponseWriter, r *http.Request) {
	limit, cursor := httpx.Paging(r, 50, 500)
	tags := map[string]string{}
	for _, kv := range r.URL.Query()["tag"] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			httpx.BadRequest(w, "tag filter must be key=value")
			return
		}
		tags[k] = v
	}
	f := ListFilter{Tags: tags, Kind: r.URL.Query().Get("kind"), Status: r.URL.Query().Get("status"),
		OSFamily: r.URL.Query().Get("os_family"), Query: r.URL.Query().Get("q")}
	switch f.Kind {
	case "", "host", "database":
	default:
		httpx.BadRequest(w, "kind must be host or database")
		return
	}
	switch f.Status {
	case "", "active", "disabled":
	default:
		httpx.BadRequest(w, "status must be active or disabled")
		return
	}
	items, next, err := h.Repo.List(r.Context(), cursor, limit, f)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[*Target]{Items: items, NextCursor: next})
}

func (h *AdminHandler) create(w http.ResponseWriter, r *http.Request) {
	var body Write
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	p, _ := auth.FromContext(r.Context())
	t := &Target{CreatedBy: &p.User.ID}
	body.apply(t)
	if err := h.Repo.Create(r.Context(), t); err != nil {
		h.writeErr(w, r, err)
		return
	}
	h.record(r, "target.create", t.ID, audit.Success, map[string]any{"name": t.Name, "address": t.Address, "os_family": t.OSFamily})
	httpx.WriteJSON(w, http.StatusCreated, t)
}

func (h *AdminHandler) get(w http.ResponseWriter, r *http.Request) {
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

func (h *AdminHandler) update(w http.ResponseWriter, r *http.Request) {
	var body Write
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	before := map[string]any{"name": t.Name, "address": t.Address, "status": t.Status}
	body.apply(t)
	if err := h.Repo.Update(r.Context(), t); err != nil {
		h.writeErr(w, r, err)
		return
	}
	details := map[string]any{"before": before, "after": map[string]any{"name": t.Name, "address": t.Address, "status": t.Status}}
	if before["address"] != t.Address {
		// Repo.Update cleared the host key and certificate pins with it.
		details["trust_reset"] = true
	}
	h.record(r, "target.update", t.ID, audit.Success, details)
	httpx.WriteJSON(w, http.StatusOK, t)
}

func (h *AdminHandler) delete(w http.ResponseWriter, r *http.Request) {
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	blocked, err := h.deleteBlockedBy(r.Context(), t.ID)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	if blocked != "" {
		h.record(r, "target.delete", t.ID, audit.Failure, map[string]any{"name": t.Name, "reason": "in_use"})
		httpx.WriteError(w, http.StatusConflict, "in_use", blocked)
		return
	}
	if err := h.Repo.Delete(r.Context(), t.ID); err != nil {
		h.writeErr(w, r, err)
		return
	}
	h.record(r, "target.delete", t.ID, audit.Success, map[string]any{"name": t.Name, "address": t.Address})
	w.WriteHeader(http.StatusNoContent)
}

// deleteBlockedBy explains why the target cannot be retired yet: policies that
// name it by id and sessions still open on it. Empty means it may go.
func (h *AdminHandler) deleteBlockedBy(ctx context.Context, id string) (string, error) {
	var policies []string
	if h.Policies != nil {
		var err error
		if policies, err = h.Policies.Referencing(ctx, id, ""); err != nil {
			return "", err
		}
	}
	open := 0
	if h.Live != nil {
		for _, l := range h.Live.List() {
			if l.TargetID == id {
				open++
			}
		}
	}
	return InUseMessage("target", policies, open), nil
}

// InUseMessage words the 409 an admin sees when a target or autoscaling
// group cannot be deleted: which policies name it by id and how many sessions
// are open on it. Empty when nothing stands in the way. Autoscaling groups
// share it so both dialogs read the same.
func InUseMessage(kind string, policies []string, openSessions int) string {
	var parts []string
	switch n := len(policies); {
	case n == 1:
		parts = append(parts, "policy "+policies[0]+" names it")
	case n > 1:
		parts = append(parts, "policies "+strings.Join(policies, ", ")+" name it")
	}
	switch {
	case openSessions == 1:
		parts = append(parts, "1 session is open on it")
	case openSessions > 1:
		parts = append(parts, fmt.Sprintf("%d sessions are open on it", openSessions))
	}
	if len(parts) == 0 {
		return ""
	}
	return fmt.Sprintf("the %s is still in use: %s. Remove it from those policies and end the sessions, then delete again.", kind, strings.Join(parts, "; "))
}

// ProbeResponse pairs the refreshed target with what the probe saw.
type ProbeResponse struct {
	Target             *Target       `json:"target"`
	Probe              ProbeResult   `json:"probe"`
	HostKeyStatus      HostKeyStatus `json:"host_key_status"`
	HostKeyFingerprint *string       `json:"host_key_fingerprint"`
	HostKeyChangedFrom *string       `json:"host_key_changed_from,omitempty"`
}

func (h *AdminHandler) probe(w http.ResponseWriter, r *http.Request) {
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	res, err := h.Prober.Probe(r.Context(), t.Address, t.EffectivePorts(), ProbeTimeout)
	if err != nil {
		h.record(r, "target.probe", t.ID, audit.Failure, map[string]any{"address": t.Address, "error": err.Error()})
		if errors.Is(err, ErrAddressForbidden) {
			httpx.WriteError(w, http.StatusUnprocessableEntity, "address_forbidden", err.Error())
			return
		}
		httpx.WriteError(w, http.StatusBadGateway, "probe_failed", err.Error())
		return
	}
	t, change, err := h.Repo.RecordProbe(r.Context(), t.ID, res)
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	h.record(r, "target.probe", t.ID, audit.Success, map[string]any{
		"address": t.Address, "capabilities": res.Capabilities, "host_key_status": change.Status,
		"host_key_fingerprint": change.New, "tls_fingerprint": t.TLSFingerprint,
	})
	out := ProbeResponse{Target: t, Probe: res, HostKeyStatus: t.HostKeyStatus, HostKeyFingerprint: t.HostKeyFingerprint}
	if change.Changed {
		out.HostKeyChangedFrom = change.Old
		h.record(r, "target.hostkey.changed", t.ID, audit.Failure, map[string]any{
			"address": t.Address, "old": change.Old, "new": change.New,
			"note": "trusted host key replaced; connections refused until an admin re-trusts",
		})
		h.Log.Warn("ssh host key changed", "target", t.Name, "address", t.Address, "old", change.Old, "new", change.New)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// CertificateProbe is the result of a certificate login attempt (ADR 0022).
type CertificateProbe struct {
	Accepted  bool   `json:"accepted"`
	Key       string `json:"key"`        // current or pending
	LoginUser string `json:"login_user"` // the principal the certificate carried
	// Reason on failure: certificate_rejected (the target does not trust the
	// authority, or the login user is not permitted), host_key_mismatch, or
	// unreachable.
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`
}

// certificateProbeValidity is how long a probe certificate lives: one
// handshake, and the key id names it as a probe in the target's log.
const certificateProbeValidity = time.Minute

// probeCertificate signs in to the target once with a certificate minted by
// the authority bound to its SSH slot, then disconnects. It answers whether
// the target trusts that authority: after installing the public key, or
// during a rotation with key=pending, before cutting over. It is a real
// login (the target's auth log shows it), so it is admin-only, only for a
// trusted host key, and audited.
func (h *AdminHandler) probeCertificate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key string `json:"key"`
	}
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(r, &body); err != nil {
			httpx.BadRequest(w, err.Error())
			return
		}
	}
	if body.Key == "" {
		body.Key = "current"
	}
	if body.Key != "current" && body.Key != "pending" {
		httpx.BadRequest(w, "key must be current or pending")
		return
	}
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	if t.HostKeyStatus != HostKeyTrusted || t.HostKeyFingerprint == nil || *t.HostKeyFingerprint == "" {
		httpx.WriteError(w, http.StatusConflict, "host_key_untrusted", "probe and trust the host key first")
		return
	}
	credID := t.Credentials[SSH]
	if credID == "" || h.Vault == nil {
		httpx.WriteError(w, http.StatusConflict, "no_credential", "no credential is bound to the target's SSH slot")
		return
	}
	cred, err := h.Vault.Get(r.Context(), credID)
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	if cred.Type != credential.TypeSSHCA {
		httpx.WriteError(w, http.StatusConflict, "not_certificate_authority", "the SSH credential is not a certificate authority")
		return
	}
	// The same rule as a session: the credential's login user, else the
	// caller's own username.
	p, _ := auth.FromContext(r.Context())
	loginUser := cred.Username
	if loginUser == "" {
		loginUser = p.User.Username
	}
	if !cred.PermitsPrincipal(loginUser) {
		httpx.WriteError(w, http.StatusForbidden, "login_user_not_permitted", "this certificate authority does not issue certificates for login user "+loginUser)
		return
	}
	if _, err := h.Prober.resolve(r.Context(), t.Address); err != nil {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "address_forbidden", err.Error())
		return
	}
	var opened *credential.Opened
	if body.Key == "pending" {
		opened, err = h.Vault.OpenPending(r.Context(), credID)
	} else {
		opened, err = h.Vault.Open(r.Context(), credID)
	}
	if err != nil {
		if errors.Is(err, credential.ErrNoRotation) {
			httpx.WriteError(w, http.StatusConflict, "no_rotation", "no next key is prepared for this authority")
			return
		}
		h.serverError(w, r, err)
		return
	}
	defer opened.Close()
	certLine, keyPEM, err := sshca.IssueForSession(opened.PrivateKey, sshca.CertParams{Principals: []string{loginUser}, Validity: certificateProbeValidity,
		KeyID: "zanskar-probe:" + p.User.Username + ":" + loginUser})
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	out := CertificateProbe{Key: body.Key, LoginUser: loginUser}
	client, err := sshgw.Dial(r.Context(), sshgw.Endpoint{Address: t.Address, Port: t.EffectivePorts()[SSH], HostKeyFingerprint: *t.HostKeyFingerprint, HostKeyTrusted: true},
		sshgw.Auth{Username: loginUser, PrivateKey: []byte(keyPEM), Certificate: []byte(certLine)}, ProbeTimeout)
	switch {
	case err == nil:
		_ = client.Close()
		out.Accepted = true
	case errors.Is(err, sshgw.ErrHostKeyMismatch):
		out.Reason, out.Error = "host_key_mismatch", "the host key does not match the trusted fingerprint"
	case errors.Is(err, sshgw.ErrAuthFailed):
		out.Reason, out.Error = "certificate_rejected", "the target refused the certificate: it does not trust this authority's public key, or the login user is not allowed"
	default:
		out.Reason, out.Error = "unreachable", "could not connect to the target"
	}
	outcome := audit.Success
	if !out.Accepted {
		outcome = audit.Failure
	}
	h.record(r, "target.probe.certificate", t.ID, outcome, map[string]any{"address": t.Address, "credential_id": credID, "key": body.Key, "login_user": loginUser, "reason": out.Reason})
	httpx.WriteJSON(w, http.StatusOK, out)
}

type trustBody struct {
	HostKeyFingerprint string `json:"host_key_fingerprint"`
}

func (h *AdminHandler) trustHostKey(w http.ResponseWriter, r *http.Request) {
	var body trustBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if body.HostKeyFingerprint == "" {
		httpx.BadRequest(w, "host_key_fingerprint required")
		return
	}
	t, err := h.Repo.TrustHostKey(r.Context(), r.PathValue("id"), body.HostKeyFingerprint)
	if err != nil {
		h.record(r, "target.hostkey.trust", r.PathValue("id"), audit.Failure, map[string]any{"fingerprint": body.HostKeyFingerprint, "error": err.Error()})
		h.writeErr(w, r, err)
		return
	}
	h.record(r, "target.hostkey.trust", t.ID, audit.Success, map[string]any{"address": t.Address, "fingerprint": body.HostKeyFingerprint})
	httpx.WriteJSON(w, http.StatusOK, t)
}

type credentialBody struct {
	CredentialID string `json:"credential_id"`
}

func (h *AdminHandler) setCredential(w http.ResponseWriter, r *http.Request) {
	var body credentialBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	id, proto := r.PathValue("id"), Protocol(r.PathValue("protocol"))
	if body.CredentialID == credential.UserSuppliedSentinel && h.Vault != nil {
		p, _ := auth.FromContext(r.Context())
		cid, err := h.Vault.EnsureUserSupplied(r.Context(), p.User.ID)
		if err != nil {
			h.serverError(w, r, err)
			return
		}
		body.CredentialID = cid
	}
	if err := h.Repo.SetCredential(r.Context(), id, proto, body.CredentialID); err != nil {
		h.writeErr(w, r, err)
		return
	}
	h.record(r, "target.credential.set", id, audit.Success, map[string]any{"protocol": proto, "credential_id": body.CredentialID})
	t, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

func (h *AdminHandler) unsetCredential(w http.ResponseWriter, r *http.Request) {
	id, proto := r.PathValue("id"), Protocol(r.PathValue("protocol"))
	if !ValidProtocol(proto) {
		httpx.BadRequest(w, "unknown protocol")
		return
	}
	if err := h.Repo.UnsetCredential(r.Context(), id, proto); err != nil {
		h.writeErr(w, r, err)
		return
	}
	h.record(r, "target.credential.unset", id, audit.Success, map[string]any{"protocol": proto})
	w.WriteHeader(http.StatusNoContent)
}

// ---- helpers

func (h *AdminHandler) record(r *http.Request, action, id string, outcome audit.Outcome, details any) {
	if h.Audit == nil {
		return
	}
	actor := audit.Actor{IP: auth.ClientIP(r)}
	if p, ok := auth.FromContext(r.Context()); ok {
		actor.UserID = p.User.ID
	}
	if _, err := h.Audit.Record(r.Context(), actor.Event(action, "target", id, outcome, details)); err != nil {
		h.Log.Error("audit record failed", "action", action, "err", err)
	}
}

func (h *AdminHandler) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "target not found")
	case errors.Is(err, ErrDuplicate):
		httpx.WriteError(w, http.StatusConflict, "duplicate", "a target with that name exists")
	case errors.Is(err, ErrInvalid):
		httpx.BadRequest(w, strings.TrimPrefix(err.Error(), "target: invalid: "))
	case errors.Is(err, ErrInvalidCredential):
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invalid_credential", "credential does not exist")
	case errors.Is(err, ErrFingerprintMismatch):
		httpx.WriteError(w, http.StatusConflict, "fingerprint_mismatch", "the fingerprint does not match the key awaiting trust; probe again and review")
	case errors.Is(err, ErrNoPendingHostKey):
		httpx.WriteError(w, http.StatusConflict, "no_pending_host_key", "no host key is awaiting trust")
	default:
		h.serverError(w, r, err)
	}
}

func (h *AdminHandler) serverError(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.Error("target handler", "path", r.URL.Path, "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
}
