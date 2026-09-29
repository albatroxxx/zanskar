// SPDX-License-Identifier: Apache-2.0

package recstorage

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

// Handler serves the admin routes for recording storage.
type Handler struct {
	Manager *Manager
	Audit   *audit.Log
	Log     *slog.Logger
}

// Register mounts the routes; all admin-only.
func (h *Handler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/admin/storage", admin(http.HandlerFunc(h.get)))
	mux.Handle("PUT /api/v1/admin/storage", admin(http.HandlerFunc(h.put)))
	mux.Handle("DELETE /api/v1/admin/storage", admin(http.HandlerFunc(h.reset)))
	mux.Handle("POST /api/v1/admin/storage/test", admin(http.HandlerFunc(h.test)))
	mux.Handle("POST /api/v1/admin/storage/move", admin(http.HandlerFunc(h.move)))
}

// Status is what the console shows.
type Status struct {
	Source string  `json:"source"` // console | environment | local
	Active *Config `json:"active,omitempty"`
	// Environment is the environment's configuration, when there is one,
	// so the card can say what Reset would go back to.
	Environment *Config        `json:"environment,omitempty"`
	Counts      map[string]int `json:"counts"` // recordings per store
	Move        Move           `json:"move"`
}

func (h *Handler) status(r *http.Request) (Status, error) {
	counts, err := h.Manager.Sessions.CountRecordingsByStore(r.Context())
	if err != nil {
		return Status{}, err
	}
	s := Status{Source: h.Manager.Source(), Active: h.Manager.Active(), Counts: counts, Move: h.Manager.MoveState()}
	if h.Manager.Env != nil {
		e := h.Manager.Env.Public()
		s.Environment = &e
	}
	return s, nil
}

func (h *Handler) write(w http.ResponseWriter, r *http.Request, code int) {
	s, err := h.status(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, code, s)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) { h.write(w, r, http.StatusOK) }

func (h *Handler) decode(w http.ResponseWriter, r *http.Request) (Config, bool) {
	var c Config
	if err := httpx.DecodeJSON(r, &c); err != nil {
		httpx.BadRequest(w, err.Error())
		return c, false
	}
	return c, true
}

func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
	c, ok := h.decode(w, r)
	if !ok {
		return
	}
	if c.Auth == AuthKeys && c.SecretAccessKey == "" {
		// A test of the stored configuration with its stored secret.
		if cur, err := h.Manager.Repo.Get(r.Context()); err == nil && cur != nil && cur.AccessKeyID == strings.TrimSpace(c.AccessKeyID) {
			c.SecretAccessKey = cur.SecretAccessKey
		}
	}
	if err := h.Manager.Test(r.Context(), c); err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "bucket": c.Bucket, "prefix": c.Prefix})
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	c, ok := h.decode(w, r)
	if !ok {
		return
	}
	p, _ := auth.FromContext(r.Context())
	before := h.Manager.Active()
	if err := h.Manager.Apply(r.Context(), c, p.User.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	a := h.Manager.Active()
	h.record(r, "recording.storage.update", map[string]any{"before": before, "after": a})
	h.write(w, r, http.StatusOK)
}

func (h *Handler) reset(w http.ResponseWriter, r *http.Request) {
	before := h.Manager.Active()
	if err := h.Manager.Reset(r.Context()); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, "recording.storage.reset", map[string]any{"before": before, "after": h.Manager.Active(), "source": h.Manager.Source()})
	h.write(w, r, http.StatusOK)
}

func (h *Handler) move(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	actor := audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}
	err := h.Manager.StartMove(r.Context(), func(final Move) {
		if h.Audit == nil {
			return
		}
		_, _ = h.Audit.Record(r.Context(), actor.Event("recording.storage.move", "recording_storage", "gateway", audit.Success,
			map[string]any{"moved": final.Moved, "failed": final.Failed, "total": final.Total}))
	})
	if err != nil {
		if errors.Is(err, ErrBusy) {
			httpx.WriteError(w, http.StatusConflict, "move_running", "a move is already running")
			return
		}
		h.fail(w, r, err)
		return
	}
	h.write(w, r, http.StatusAccepted)
}

func (h *Handler) record(r *http.Request, action string, details map[string]any) {
	if h.Audit == nil {
		return
	}
	actor := audit.Actor{IP: auth.ClientIP(r)}
	if p, ok := auth.FromContext(r.Context()); ok {
		actor.UserID = p.User.ID
	}
	if _, err := h.Audit.Record(r.Context(), actor.Event(action, "recording_storage", "gateway", audit.Success, details)); err != nil {
		h.Log.Error("audit record failed", "action", action, "err", err)
	}
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrInvalid) {
		// The message can quote what the operator typed; one line of it.
		httpx.BadRequest(w, strings.NewReplacer("\n", " ", "\r", " ").Replace(strings.TrimPrefix(err.Error(), "recstorage: invalid configuration: ")))
		return
	}
	h.Log.Error("storage handler", "route", r.Pattern, "err", strings.NewReplacer("\n", " ", "\r", " ").Replace(err.Error()))
	httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
}
