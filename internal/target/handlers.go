// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"database/sql"
	"errors"
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
	// Policies, Requests and Live are what deleting a target reaches (ADR
	// 0036, amended 2026-10-30): the grants that name it, its open access
	// requests, its live sessions. Nil skips that part.
	Policies *policy.Repo
	Requests Requests
	Live     *gateway.Registry
	// Vault resolves the user_supplied sentinel when a slot is set to
	// prompt; nil disables the sentinel.
	Vault *credential.Vault
	// Revoker ends the live sessions a disable, an address change or a
	// changed pin withdraws (ADR 0013); nil leaves them to their own limits.
	Revoker gateway.Revoker
	Audit   *audit.Log
	Log     *slog.Logger
}

// Register mounts the routes; every one requires the admin role.
func (h *AdminHandler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/targets", admin(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/v1/targets", admin(http.HandlerFunc(h.create)))
	mux.Handle("GET /api/v1/targets/{id}", admin(http.HandlerFunc(h.get)))
	mux.Handle("PUT /api/v1/targets/{id}", admin(http.HandlerFunc(h.update)))
	mux.Handle("DELETE /api/v1/targets/{id}", admin(http.HandlerFunc(h.delete)))
	mux.Handle("GET /api/v1/targets/{id}/usage", admin(http.HandlerFunc(h.usage)))
	mux.Handle("POST /api/v1/targets/{id}/probe", admin(http.HandlerFunc(h.probe)))
	mux.Handle("POST /api/v1/targets/{id}/probe-certificate", admin(http.HandlerFunc(h.probeCertificate)))
	mux.Handle("POST /api/v1/targets/{id}/host-key/trust", admin(http.HandlerFunc(h.trustHostKey)))
	mux.Handle("POST /api/v1/targets/{id}/certificate/trust", admin(http.HandlerFunc(h.trustCertificate)))
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
	TLSCA         string              `json:"tls_ca"`         // database and application targets
	AppUpstream   string              `json:"app_upstream"`   // application targets (ADR 0034)
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
	t.AppUpstream = w.AppUpstream
	t.Ports, t.Capabilities, t.Tags = w.Ports, w.Capabilities, w.Tags
	t.Status, t.Notes, t.Credentials = w.Status, w.Notes, w.Credentials
}

func (h *AdminHandler) list(w http.ResponseWriter, r *http.Request) {
	limit, cursor := httpx.Paging(r, 50, 500)
	tags := map[string]string{}
	for _, kv := range r.URL.Query()["tag"] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			httpx.BadRequest(w, r, "tag filter must be key=value")
			return
		}
		tags[k] = v
	}
	f := ListFilter{Tags: tags, Kind: r.URL.Query().Get("kind"), Status: r.URL.Query().Get("status"),
		OSFamily: r.URL.Query().Get("os_family"), Query: r.URL.Query().Get("q"), Attention: r.URL.Query().Get("attention") == "true"}
	switch f.Kind {
	case "", KindHost, KindDatabase, KindApplication:
	default:
		httpx.BadRequest(w, r, "kind must be host, database or application")
		return
	}
	switch f.Status {
	case "", "active", "disabled":
	default:
		httpx.BadRequest(w, r, "status must be active or disabled")
		return
	}
	items, next, err := h.Repo.List(r.Context(), cursor, limit, f)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[*Target]{Items: items, NextCursor: next})
}

func (h *AdminHandler) create(w http.ResponseWriter, r *http.Request) {
	var body Write
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	p, _ := auth.FromContext(r.Context())
	t := &Target{CreatedBy: &p.User.ID}
	body.apply(t)
	if !h.addressAllowed(w, r, audit.TargetCreate, "", t) {
		return
	}
	if err := h.Repo.Create(r.Context(), t); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.TargetCreate, t.ID, audit.Success, map[string]any{"name": t.Name, "address": t.Address, "os_family": t.OSFamily})
	httpx.WriteJSON(w, http.StatusCreated, t)
}

func (h *AdminHandler) get(w http.ResponseWriter, r *http.Request) {
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

func (h *AdminHandler) update(w http.ResponseWriter, r *http.Request) {
	var body Write
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	before := map[string]any{"name": t.Name, "address": t.Address, "status": t.Status}
	body.apply(t)
	if !h.addressAllowed(w, r, audit.TargetUpdate, t.ID, t) {
		return
	}
	if err := h.Repo.Update(r.Context(), t); err != nil {
		h.fail(w, r, err)
		return
	}
	details := map[string]any{"before": before, "after": map[string]any{"name": t.Name, "address": t.Address, "status": t.Status}}
	if before["address"] != t.Address {
		// Repo.Update cleared the host key and certificate pins with it.
		details["trust_reset"] = true
	}
	// A target taken out of service, or moved to an address nobody has
	// trusted yet, keeps no session: what was admitted to the old target
	// ends now rather than at its own limits.
	if h.Revoker != nil && ((before["status"] == StatusActive && t.Status == StatusDisabled) || before["address"] != t.Address) {
		details["live_sessions_ended"] = h.Revoker.TargetDisabled(t.ID)
	}
	h.record(r, audit.TargetUpdate, t.ID, audit.Success, details)
	httpx.WriteJSON(w, http.StatusOK, t)
}

func (h *AdminHandler) delete(w http.ResponseWriter, r *http.Request) {
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var removals []policy.Removal
	var closed int64
	err = h.Repo.DeleteWith(r.Context(), t.ID, func(tx *sql.Tx) error {
		var err error
		if h.Policies != nil {
			if removals, err = h.Policies.RemoveTargetTx(r.Context(), tx, t.ID, ""); err != nil {
				return err
			}
		}
		if h.Requests != nil {
			if closed, err = h.Requests.CloseForTargetTx(r.Context(), tx, t.ID, "", "target deleted"); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	ended := EndSessions(h.Live, []string{t.ID})
	h.record(r, audit.TargetDelete, t.ID, audit.Success, DeleteDetails(map[string]any{"name": t.Name, "address": t.Address}, removals, closed, ended))
	RecordRemovals(r, h.Audit, removals, t.ID, t.Name)
	w.WriteHeader(http.StatusNoContent)
}

// usage answers GET /targets/{id}/usage: what deleting the target would
// change, for the confirmation the console shows first.
func (h *AdminHandler) usage(w http.ResponseWriter, r *http.Request) {
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	u, err := Preview(r.Context(), h.Policies, h.Requests, h.Live, t.ID, "", []string{t.ID})
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

// Requests is what deleting a target needs of the access requests: their
// count, and closing them inside the deletion's transaction.
type Requests interface {
	OpenForTarget(ctx context.Context, targetID, asgID string) (int, error)
	CloseForTargetTx(ctx context.Context, tx *sql.Tx, targetID, asgID, note string) (int64, error)
}

// Usage is what deleting a target or an autoscaling group would change.
type Usage struct {
	Policies     []policy.Removal `json:"policies"`
	LiveSessions int              `json:"live_sessions"`
	OpenRequests int              `json:"open_requests"`
}

// Preview gathers a Usage; sessionIDs are the target ids the registry keys
// the live sessions by (the target, or the group's instances).
func Preview(ctx context.Context, pols *policy.Repo, reqs Requests, live *gateway.Registry, targetID, asgID string, liveIDs []string) (Usage, error) {
	u := Usage{Policies: []policy.Removal{}}
	var err error
	if pols != nil {
		if u.Policies, err = pols.TargetUsage(ctx, targetID, asgID); err != nil {
			return u, err
		}
	}
	if reqs != nil {
		if u.OpenRequests, err = reqs.OpenForTarget(ctx, targetID, asgID); err != nil {
			return u, err
		}
	}
	if live != nil {
		ids := make(map[string]bool, len(liveIDs))
		for _, id := range liveIDs {
			ids[id] = true
		}
		for _, l := range live.List() {
			if ids[l.TargetID] {
				u.LiveSessions++
			}
		}
	}
	return u, nil
}

// EndSessions ends the live sessions on the deleted target ids, then once
// more a moment later for a connection that was redeeming its ticket as the
// deletion committed, and returns how many the first sweep ended.
func EndSessions(live *gateway.Registry, ids []string) int {
	if live == nil {
		return 0
	}
	sweep := func() int {
		n := 0
		for _, id := range ids {
			n += live.TerminateTarget(id, gateway.ErrTargetDeleted)
		}
		return n
	}
	ended := sweep()
	time.AfterFunc(2*time.Second, func() { sweep() })
	return ended
}

// DeleteDetails adds what a deletion reached to its audit details.
func DeleteDetails(details map[string]any, removals []policy.Removal, closed int64, ended int) map[string]any {
	if len(removals) > 0 {
		names := make([]string, len(removals))
		for i, rm := range removals {
			names[i] = rm.Name
		}
		details["policies_updated"] = names
	}
	if closed > 0 {
		details["requests_closed"] = closed
	}
	if ended > 0 {
		details["sessions_ended"] = ended
	}
	return details
}

// RecordRemovals audits a policy.update for each policy a deletion changed,
// so each policy's own history says why it changed.
func RecordRemovals(r *http.Request, log *audit.Log, removals []policy.Removal, removedID, removedName string) {
	if log == nil {
		return
	}
	actor := auth.ActorFor(r)
	for _, rm := range removals {
		_, _ = log.Record(r.Context(), actor.Event(audit.PolicyUpdate, "policy", rm.PolicyID, audit.Success, map[string]any{
			"name": rm.Name, "removed_target": removedID, "removed_target_name": removedName, "grants_removed": rm.GrantsRemoved, "no_grants_left": rm.NoGrantsLeft,
		}))
	}
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
		h.fail(w, r, err)
		return
	}
	res, err := h.Prober.Probe(r.Context(), t.Address, t.EffectivePorts(), ProbeTimeout)
	if err != nil {
		h.record(r, audit.TargetProbe, t.ID, audit.Failure, map[string]any{"address": t.Address, "error": err.Error()})
		if errors.Is(err, ErrAddressForbidden) {
			httpx.WriteError(w, r, http.StatusUnprocessableEntity, "address_forbidden", err.Error())
			return
		}
		httpx.WriteError(w, r, http.StatusBadGateway, "probe_failed", err.Error())
		return
	}
	t, change, err := h.Repo.RecordProbe(r.Context(), t.ID, res)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.TargetProbe, t.ID, audit.Success, map[string]any{
		"address": t.Address, "capabilities": res.Capabilities, "host_key_status": change.Status,
		"host_key_fingerprint": change.New, "tls_fingerprint": t.TLSFingerprint,
	})
	out := ProbeResponse{Target: t, Probe: res, HostKeyStatus: t.HostKeyStatus, HostKeyFingerprint: t.HostKeyFingerprint}
	// A pin that moved is the signal that the host may not be the one that
	// was trusted; the sessions already open on it end with it (ADR 0013).
	ended := 0
	if h.Revoker != nil && (change.Changed || len(change.Certificates) > 0) {
		ended = h.Revoker.TargetTrustLost(t.ID)
	}
	for _, c := range change.Certificates {
		h.record(r, audit.TargetTLSChanged, t.ID, audit.Failure, map[string]any{
			"address": t.Address, "protocol": c.Protocol, "pinned": c.Pinned, "seen": c.Seen, "live_sessions_ended": ended,
		})
		h.Log.Warn("pinned certificate changed; the new one awaits confirmation", "target", t.Name, "protocol", c.Protocol, "pinned", c.Pinned, "seen", c.Seen)
	}
	if change.Changed {
		out.HostKeyChangedFrom = change.Old
		h.record(r, audit.TargetHostKeyChanged, t.ID, audit.Failure, map[string]any{
			"address": t.Address, "old": change.Old, "new": change.New, "live_sessions_ended": ended,
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
			httpx.BadRequest(w, r, err.Error())
			return
		}
	}
	if body.Key == "" {
		body.Key = "current"
	}
	if body.Key != "current" && body.Key != "pending" {
		httpx.BadRequest(w, r, "key must be current or pending")
		return
	}
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if t.HostKeyStatus != HostKeyTrusted || t.HostKeyFingerprint == nil || *t.HostKeyFingerprint == "" {
		httpx.WriteError(w, r, http.StatusConflict, "host_key_untrusted", "probe and trust the host key first")
		return
	}
	credID := t.Credentials[SSH]
	if credID == "" || h.Vault == nil {
		httpx.WriteError(w, r, http.StatusConflict, "no_credential", "no credential is bound to the target's SSH slot")
		return
	}
	cred, err := h.Vault.Get(r.Context(), credID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if cred.Type != credential.TypeSSHCA {
		httpx.WriteError(w, r, http.StatusConflict, "not_certificate_authority", "the SSH credential is not a certificate authority")
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
		httpx.WriteError(w, r, http.StatusForbidden, "login_user_not_permitted", "this certificate authority does not issue certificates for login user "+loginUser)
		return
	}
	// The login goes to the address checked here: dialling the name would
	// look it up a second time, and the answer could have changed.
	dialIP, err := h.Prober.Resolve(r.Context(), t.Address)
	if err != nil {
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, "address_forbidden", err.Error())
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
			httpx.WriteError(w, r, http.StatusConflict, "no_rotation", "no next key is prepared for this authority")
			return
		}
		httpx.Internal(w, r, h.Log, err)
		return
	}
	defer opened.Close()
	certLine, keyPEM, err := sshca.IssueForSession(opened.PrivateKey, sshca.CertParams{Principals: []string{loginUser}, Validity: certificateProbeValidity,
		KeyID: "zanskar-probe:" + p.User.Username + ":" + loginUser})
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	out := CertificateProbe{Key: body.Key, LoginUser: loginUser}
	client, err := sshgw.Dial(r.Context(), sshgw.Endpoint{Address: dialIP.String(), Port: t.EffectivePorts()[SSH], HostKeyFingerprint: *t.HostKeyFingerprint, HostKeyTrusted: true},
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
	h.record(r, audit.TargetProbeCertificate, t.ID, outcome, map[string]any{"address": t.Address, "credential_id": credID, "key": body.Key, "login_user": loginUser, "reason": out.Reason})
	httpx.WriteJSON(w, http.StatusOK, out)
}

type trustBody struct {
	HostKeyFingerprint string `json:"host_key_fingerprint"`
}

func (h *AdminHandler) trustHostKey(w http.ResponseWriter, r *http.Request) {
	var body trustBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	if body.HostKeyFingerprint == "" {
		httpx.BadRequest(w, r, "host_key_fingerprint required")
		return
	}
	t, err := h.Repo.TrustHostKey(r.Context(), r.PathValue("id"), body.HostKeyFingerprint)
	if err != nil {
		h.record(r, audit.TargetHostKeyTrust, r.PathValue("id"), audit.Failure, map[string]any{"fingerprint": body.HostKeyFingerprint, "error": err.Error()})
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.TargetHostKeyTrust, t.ID, audit.Success, map[string]any{"address": t.Address, "fingerprint": body.HostKeyFingerprint})
	httpx.WriteJSON(w, http.StatusOK, t)
}

type certificateTrustBody struct {
	Protocol    Protocol `json:"protocol"` // rdp or winrm
	Fingerprint string   `json:"fingerprint"`
}

// trustCertificate pins the RDP or WinRM certificate a probe held as pending
// (ADR 0012); the administrator presents the fingerprint they checked.
func (h *AdminHandler) trustCertificate(w http.ResponseWriter, r *http.Request) {
	var body certificateTrustBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	if body.Fingerprint == "" {
		httpx.BadRequest(w, r, "fingerprint required")
		return
	}
	t, err := h.Repo.TrustCertificate(r.Context(), r.PathValue("id"), body.Protocol, body.Fingerprint)
	if err != nil {
		h.record(r, audit.TargetTLSTrust, r.PathValue("id"), audit.Failure, map[string]any{"protocol": body.Protocol, "fingerprint": body.Fingerprint, "error": err.Error()})
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.TargetTLSTrust, t.ID, audit.Success, map[string]any{"address": t.Address, "protocol": body.Protocol, "fingerprint": body.Fingerprint})
	httpx.WriteJSON(w, http.StatusOK, t)
}

type credentialBody struct {
	CredentialID string `json:"credential_id"`
}

func (h *AdminHandler) setCredential(w http.ResponseWriter, r *http.Request) {
	var body credentialBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	id, proto := r.PathValue("id"), Protocol(r.PathValue("protocol"))
	if body.CredentialID == credential.UserSuppliedSentinel && h.Vault != nil {
		p, _ := auth.FromContext(r.Context())
		cid, err := h.Vault.EnsureUserSupplied(r.Context(), p.User.ID)
		if err != nil {
			httpx.Internal(w, r, h.Log, err)
			return
		}
		body.CredentialID = cid
	}
	if err := h.Repo.SetCredential(r.Context(), id, proto, body.CredentialID); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.TargetCredentialSet, id, audit.Success, map[string]any{"protocol": proto, "credential_id": body.CredentialID})
	t, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

func (h *AdminHandler) unsetCredential(w http.ResponseWriter, r *http.Request) {
	id, proto := r.PathValue("id"), Protocol(r.PathValue("protocol"))
	if !ValidProtocol(proto) {
		httpx.BadRequest(w, r, "unknown protocol")
		return
	}
	if err := h.Repo.UnsetCredential(r.Context(), id, proto); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.TargetCredentialUnset, id, audit.Success, map[string]any{"protocol": proto})
	w.WriteHeader(http.StatusNoContent)
}

// ---- helpers

// addressAllowed refuses, before anything is saved, an address that is an IP
// literal the gateway must never connect to, answering as the probe does. A
// database target is never probed, so for one this is the only check its
// address meets before a session; a name is checked each time it resolves.
func (h *AdminHandler) addressAllowed(w http.ResponseWriter, r *http.Request, action, id string, t *Target) bool {
	err := h.Prober.CheckLiteral(t.Address)
	if err == nil {
		return true
	}
	h.record(r, action, id, audit.Failure, map[string]any{"name": t.Name, "address": strings.TrimSpace(t.Address), "reason": "address_forbidden"})
	h.fail(w, r, err)
	return false
}

func (h *AdminHandler) record(r *http.Request, action, id string, outcome audit.Outcome, details any) {
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(action, "target", id, outcome, details))
}

func (h *AdminHandler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "target not found")
	case errors.Is(err, ErrDuplicate):
		httpx.WriteError(w, r, http.StatusConflict, "conflict", "a target with that name exists")
	case errors.Is(err, ErrInvalid):
		httpx.BadRequest(w, r, strings.TrimPrefix(err.Error(), "target: invalid: "))
	case errors.Is(err, ErrInvalidCredential):
		httpx.BadRequest(w, r, "credential does not exist")
	case errors.Is(err, ErrAddressForbidden):
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, "address_forbidden", err.Error())
	case errors.Is(err, ErrFingerprintMismatch):
		httpx.WriteError(w, r, http.StatusConflict, "fingerprint_mismatch", "the fingerprint does not match the one awaiting trust; probe again and review")
	case errors.Is(err, ErrNoPendingHostKey):
		httpx.WriteError(w, r, http.StatusConflict, "no_pending_host_key", "no host key is awaiting trust")
	case errors.Is(err, ErrNoPendingCertificate):
		httpx.WriteError(w, r, http.StatusConflict, "no_pending_certificate", "no certificate is awaiting trust for that protocol")
	default:
		httpx.Internal(w, r, h.Log, err)
	}
}
