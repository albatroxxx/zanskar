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
	Repo  *Repo
	Audit *audit.Log
	Log   *slog.Logger
}

// Register mounts the routes. The banner is read before anyone is signed
// in, so its GET under /system is deliberately unauthenticated; it returns
// text an administrator chose to show to everyone anyway.
func (h *Handler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/admin/settings/login-banner", admin(http.HandlerFunc(h.getLoginBanner)))
	mux.Handle("PUT /api/v1/admin/settings/login-banner", admin(http.HandlerFunc(h.setLoginBanner)))
	mux.HandleFunc("GET /api/v1/system/banner", h.publicBanner)
}

// Banner is the public shape: the text only, nothing about who set it.
type Banner struct {
	Text string `json:"text"`
}

func (h *Handler) publicBanner(w http.ResponseWriter, r *http.Request) {
	s, err := h.Repo.Get(r.Context(), KeyLoginBanner)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, Banner{Text: s.Value})
}

func (h *Handler) getLoginBanner(w http.ResponseWriter, r *http.Request) {
	s, err := h.Repo.Get(r.Context(), KeyLoginBanner)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s)
}

func (h *Handler) setLoginBanner(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Value string `json:"value"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	p, _ := auth.FromContext(r.Context())
	before, err := h.Repo.Get(r.Context(), KeyLoginBanner)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	s, err := h.Repo.Set(r.Context(), KeyLoginBanner, in.Value, p.User.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// The banner is not a secret; the audit row keeps what was shown, since
	// "what did the sign-in page say on that day" is the compliance question.
	h.record(r, "settings.update", KeyLoginBanner, map[string]any{"before": before.Value, "after": s.Value, "length": len(s.Value)})
	httpx.WriteJSON(w, http.StatusOK, s)
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
	if errors.Is(err, ErrInvalid) {
		httpx.BadRequest(w, strings.TrimPrefix(err.Error(), "settings: invalid value: "))
		return
	}
	// The matched route pattern names the handler without echoing the
	// request's own path into the log.
	h.Log.Error("settings handler", "route", r.Method+" "+r.Pattern, "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
}
