// SPDX-License-Identifier: Apache-2.0

package target

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

// ProbeTimeout bounds one admin-triggered probe.
const ProbeTimeout = 5 * time.Second

// AdminHandler serves /api/v1/targets for the admin role.
type AdminHandler struct {
	Repo   *Repo
	Prober *Prober
	Audit  *audit.Log
	Log    *slog.Logger
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
	items, next, err := h.Repo.List(r.Context(), cursor, limit, tags)
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
	h.record(r, "target.update", t.ID, audit.Success, map[string]any{"before": before, "after": map[string]any{"name": t.Name, "address": t.Address, "status": t.Status}})
	httpx.WriteJSON(w, http.StatusOK, t)
}

func (h *AdminHandler) delete(w http.ResponseWriter, r *http.Request) {
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	if err := h.Repo.Delete(r.Context(), t.ID); err != nil {
		h.writeErr(w, r, err)
		return
	}
	h.record(r, "target.delete", t.ID, audit.Success, map[string]any{"name": t.Name, "address": t.Address})
	w.WriteHeader(http.StatusNoContent)
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
