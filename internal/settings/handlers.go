// SPDX-License-Identifier: Apache-2.0

package settings

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

// Handler serves the admin settings routes and the one public read the
// sign-in page needs.
type Handler struct {
	Service *Service
	Audit   *audit.Log
	Log     *slog.Logger
}

// Register mounts the routes. The banner is read before anyone is signed
// in, so its GET under /system is deliberately unauthenticated; it returns
// text an administrator chose to show to everyone anyway. The login-banner
// routes remain as aliases of the generic ones for clients that used them.
func (h *Handler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/admin/settings", admin(http.HandlerFunc(h.list)))
	mux.Handle("PUT /api/v1/admin/settings/{key}", admin(http.HandlerFunc(h.set)))
	mux.Handle("DELETE /api/v1/admin/settings/{key}", admin(http.HandlerFunc(h.reset)))
	mux.Handle("GET /api/v1/admin/settings/login-banner", admin(http.HandlerFunc(h.getLoginBanner)))
	mux.HandleFunc("GET /api/v1/system/banner", h.publicBanner)
}

// Banner is the public shape: the text only, nothing about who set it.
type Banner struct {
	Text string `json:"text"`
}

func (h *Handler) publicBanner(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, Banner{Text: h.Service.String(KeyLoginBanner)})
}

// listing is what the panel renders: every runtime setting resolved, and the
// install-time settings read-only.
type listing struct {
	Runtime []Value `json:"runtime"`
	Boot    []Boot  `json:"boot"`
}

func (h *Handler) list(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, listing{Runtime: h.Service.All(), Boot: h.Service.BootSettings()})
}

func (h *Handler) getLoginBanner(w http.ResponseWriter, _ *http.Request) {
	v, _ := h.Service.Get(KeyLoginBanner)
	httpx.WriteJSON(w, http.StatusOK, v)
}

// key resolves the path key; a boot key is refused with the reason, since
// the panel never writes the environment file (ADR 0020).
func (h *Handler) key(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := r.PathValue("key")
	if key == "login-banner" {
		key = KeyLoginBanner
	}
	if _, ok := Lookup(key); ok {
		return key, true
	}
	for _, b := range h.Service.BootSettings() {
		if b.Key == key {
			httpx.WriteError(w, http.StatusConflict, "boot_setting",
				"this setting is fixed at install: edit "+b.EnvVar+" in the service's environment file and restart the gateway")
			return "", false
		}
	}
	httpx.WriteError(w, http.StatusNotFound, "not_found", "no such setting")
	return "", false
}

func (h *Handler) set(w http.ResponseWriter, r *http.Request) {
	key, ok := h.key(w, r)
	if !ok {
		return
	}
	var in struct {
		Value string `json:"value"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	p, _ := auth.FromContext(r.Context())
	before, _ := h.Service.Get(key)
	v, err := h.Service.Set(r.Context(), key, in.Value, p.User.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// None of the runtime settings is a secret; the audit row keeps both
	// values, since "what was it set to that day" is the compliance question.
	h.record(r, "settings.update", key, map[string]any{"before": before.Value, "before_source": before.Source, "after": v.Value})
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (h *Handler) reset(w http.ResponseWriter, r *http.Request) {
	key, ok := h.key(w, r)
	if !ok {
		return
	}
	before, _ := h.Service.Get(key)
	v, err := h.Service.Reset(r.Context(), key)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "settings.reset", key, map[string]any{"before": before.Value, "after": v.Value, "after_source": v.Source})
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (h *Handler) record(r *http.Request, action, key string, details map[string]any) {
	if h.Audit == nil {
		return
	}
	actor := audit.Actor{IP: auth.ClientIP(r)}
	if p, ok := auth.FromContext(r.Context()); ok {
		actor.UserID = p.User.ID
	}
	if _, err := h.Audit.Record(r.Context(), actor.Event(action, "setting", key, audit.Success, details)); err != nil {
		h.Log.Error("audit record failed", "action", action, "err", err)
	}
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrInvalid):
		httpx.BadRequest(w, strings.TrimPrefix(err.Error(), "settings: invalid value: "))
	case errors.Is(err, ErrUnknown):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "no such setting")
	default:
		// The matched route pattern names the handler without echoing the
		// request's own path into the log.
		h.Log.Error("settings handler", "route", r.Method+" "+r.Pattern, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}
