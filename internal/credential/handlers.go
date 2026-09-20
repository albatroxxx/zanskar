// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

// AdminHandler serves /api/v1/credentials for the admin role.
type AdminHandler struct {
	Vault *Vault
	Audit *audit.Log
	Log   *slog.Logger
}

// Register mounts the routes behind the admin role.
func (h *AdminHandler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/credentials", admin(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/v1/credentials", admin(http.HandlerFunc(h.create)))
	mux.Handle("POST /api/v1/credentials/generate-ssh-key", admin(http.HandlerFunc(h.generateSSHKey)))
	mux.Handle("GET /api/v1/credentials/{id}", admin(http.HandlerFunc(h.get)))
	mux.Handle("PUT /api/v1/credentials/{id}", admin(http.HandlerFunc(h.update)))
	mux.Handle("PATCH /api/v1/credentials/{id}", admin(http.HandlerFunc(h.update)))
	mux.Handle("DELETE /api/v1/credentials/{id}", admin(http.HandlerFunc(h.delete)))
	mux.Handle("POST /api/v1/credentials/{id}/rotate", admin(http.HandlerFunc(h.rotate)))
}

// writeRequest is the write-only body. Secret fields are never echoed back.
type writeRequest struct {
	Name                 string `json:"name"`
	Type                 Type   `json:"type,omitempty"`
	Mode                 Mode   `json:"mode,omitempty"`
	Username             string `json:"username,omitempty"`
	Domain               string `json:"domain,omitempty"`
	Password             string `json:"password,omitempty"`
	PrivateKey           string `json:"private_key,omitempty"`
	PrivateKeyPassphrase string `json:"private_key_passphrase,omitempty"`
}

func (r *writeRequest) secret() *Secret {
	return &Secret{Password: r.Password, PrivateKey: r.PrivateKey, Passphrase: r.PrivateKeyPassphrase}
}

func (h *AdminHandler) list(w http.ResponseWriter, r *http.Request) {
	limit, cursor := httpx.Paging(r, 50, 500)
	items, next, err := h.Vault.List(r.Context(), cursor, limit)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[*Credential]{Items: items, NextCursor: next})
}

func (h *AdminHandler) create(w http.ResponseWriter, r *http.Request) {
	var req writeRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	c := &Credential{Name: req.Name, Type: req.Type, Mode: req.Mode, Username: req.Username, Domain: req.Domain}
	s := req.secret()
	generated := false
	// Per the API spec, omitting the key for a vaulted ssh_key or ssh_ca means
	// "generate one"; the admin only ever sees the public half.
	if c.Mode == ModeVaulted && (c.Type == TypeSSHKey || c.Type == TypeSSHCA) && s.PrivateKey == "" && s.Password == "" {
		pemText, err := GenerateSSHKey()
		if err != nil {
			h.serverError(w, r, err)
			return
		}
		s.PrivateKey, generated = pemText, true
	}
	p, _ := auth.FromContext(r.Context())
	if err := h.Vault.Create(r.Context(), c, s, p.User.ID); err != nil {
		h.writeErr(w, r, err)
		return
	}
	h.record(r, "credential.create", c, map[string]any{"type": c.Type, "mode": c.Mode, "name": c.Name, "generated_key": generated})
	httpx.WriteJSON(w, http.StatusCreated, c)
}

type generateRequest struct {
	Name     string `json:"name"`
	Username string `json:"username"`
}

func (h *AdminHandler) generateSSHKey(w http.ResponseWriter, r *http.Request) {
	var req generateRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	pemText, err := GenerateSSHKey()
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	c := &Credential{Name: req.Name, Type: TypeSSHKey, Mode: ModeVaulted, Username: req.Username}
	p, _ := auth.FromContext(r.Context())
	if err := h.Vault.Create(r.Context(), c, &Secret{PrivateKey: pemText}, p.User.ID); err != nil {
		h.writeErr(w, r, err)
		return
	}
	h.record(r, "credential.create", c, map[string]any{"type": c.Type, "mode": c.Mode, "name": c.Name, "generated_key": true})
	httpx.WriteJSON(w, http.StatusCreated, c)
}

func (h *AdminHandler) get(w http.ResponseWriter, r *http.Request) {
	c, err := h.Vault.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

func (h *AdminHandler) update(w http.ResponseWriter, r *http.Request) {
	var req writeRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	id := r.PathValue("id")
	existing, err := h.Vault.Get(r.Context(), id)
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	if (req.Type != "" && req.Type != existing.Type) || (req.Mode != "" && req.Mode != existing.Mode) {
		httpx.BadRequest(w, "type and mode are immutable; create a new credential instead")
		return
	}
	if req.Name == "" {
		req.Name = existing.Name
	}
	if req.Username == "" {
		req.Username = existing.Username
	}
	if req.Domain == "" {
		req.Domain = existing.Domain
	}
	c, err := h.Vault.Update(r.Context(), id, req.Name, req.Username, req.Domain)
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	// A secret in the update body means rotate, as the API spec describes.
	if req.Password != "" || req.PrivateKey != "" {
		if c, err = h.Vault.Rotate(r.Context(), id, req.secret()); err != nil {
			h.writeErr(w, r, err)
			return
		}
		h.record(r, "credential.rotate", c, map[string]any{"type": c.Type, "mode": c.Mode, "name": c.Name})
	}
	h.record(r, "credential.update", c, map[string]any{"type": c.Type, "mode": c.Mode, "name": c.Name})
	httpx.WriteJSON(w, http.StatusOK, c)
}

func (h *AdminHandler) rotate(w http.ResponseWriter, r *http.Request) {
	var req writeRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	c, err := h.Vault.Rotate(r.Context(), r.PathValue("id"), req.secret())
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	h.record(r, "credential.rotate", c, map[string]any{"type": c.Type, "mode": c.Mode, "name": c.Name})
	httpx.WriteJSON(w, http.StatusOK, c)
}

func (h *AdminHandler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := h.Vault.Get(r.Context(), id)
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	if err := h.Vault.Delete(r.Context(), id); err != nil {
		h.writeErr(w, r, err)
		return
	}
	h.record(r, "credential.delete", c, map[string]any{"type": c.Type, "mode": c.Mode, "name": c.Name})
	w.WriteHeader(http.StatusNoContent)
}

// ---- helpers

func (h *AdminHandler) record(r *http.Request, action string, c *Credential, details map[string]any) {
	if h.Audit == nil {
		return
	}
	a := audit.Actor{IP: auth.ClientIP(r)}
	if p, ok := auth.FromContext(r.Context()); ok {
		a.UserID = p.User.ID
	}
	if _, err := h.Audit.Record(r.Context(), a.Event(action, "credential", c.ID, audit.Success, details)); err != nil {
		h.Log.Error("audit record failed", "action", action, "err", err)
	}
}

func (h *AdminHandler) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "credential not found")
	case errors.Is(err, ErrDuplicate):
		httpx.WriteError(w, http.StatusConflict, "conflict", "a credential with that name already exists")
	case errors.Is(err, ErrInUse):
		httpx.WriteError(w, http.StatusConflict, "in_use", "credential is still referenced by a target or autoscaling group")
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrBadKey), errors.Is(err, ErrPassphrase), errors.Is(err, ErrNoSecret):
		httpx.BadRequest(w, strings.TrimPrefix(err.Error(), "credential: "))
	default:
		h.serverError(w, r, err)
	}
}

func (h *AdminHandler) serverError(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.Error("credential handler", "path", r.URL.Path, "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
}
