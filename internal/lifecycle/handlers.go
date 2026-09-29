// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
	"github.com/albatroxxx/zanskar/internal/version"
)

// Handler serves the admin routes for the process: its status, and a
// restart with a drain.
type Handler struct {
	Drift      *Drift
	Controller *Controller
	Audit      *audit.Log
	Log        *slog.Logger
	StartedAt  time.Time
}

// Register mounts the routes; all admin-only.
func (h *Handler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/admin/system/status", admin(http.HandlerFunc(h.status)))
	mux.Handle("POST /api/v1/admin/system/restart", admin(http.HandlerFunc(h.restart)))
	mux.Handle("DELETE /api/v1/admin/system/restart", admin(http.HandlerFunc(h.cancel)))
}

// Status is what the console polls.
type Status struct {
	Version         string    `json:"version"`
	StartedAt       time.Time `json:"started_at"`
	UptimeSeconds   int64     `json:"uptime_seconds"`
	Supervisor      string    `json:"supervisor"`
	LiveSessions    int       `json:"live_sessions"`
	EnvFile         Report    `json:"env_file"`
	RestartRequired bool      `json:"restart_required"`
	Draining        bool      `json:"draining"`
	Drain           *Drain    `json:"drain,omitempty"`
}

func (h *Handler) current() Status {
	rep := h.Drift.Check()
	d := h.Controller.Current()
	return Status{
		Version: version.Version, StartedAt: h.StartedAt, UptimeSeconds: int64(time.Since(h.StartedAt).Seconds()),
		Supervisor: Supervisor(), LiveSessions: h.Controller.Registry.Count(), EnvFile: rep,
		RestartRequired: rep.RestartRequired(), Draining: d != nil, Drain: d,
	}
}

func (h *Handler) status(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, h.current())
}

func (h *Handler) restart(w http.ResponseWriter, r *http.Request) {
	var in struct {
		WaitMinutes *int `json:"wait_minutes"`
	}
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(r, &in); err != nil {
			httpx.BadRequest(w, err.Error())
			return
		}
	}
	wait := DefaultWait
	if in.WaitMinutes != nil {
		if *in.WaitMinutes < 0 || time.Duration(*in.WaitMinutes)*time.Minute > MaxWait {
			httpx.BadRequest(w, "wait_minutes must be between 0 and 240")
			return
		}
		wait = time.Duration(*in.WaitMinutes) * time.Minute
	}
	p, _ := auth.FromContext(r.Context())
	before := h.current()
	d := h.Controller.Restart(p.User.ID, wait)
	h.record(r, "system.restart", map[string]any{
		"wait_minutes": d.WaitMinutes, "live_sessions": before.LiveSessions,
		"env_file_state": before.EnvFile.State, "changed_env": before.EnvFile.Changed, "supervisor": before.Supervisor,
	})
	httpx.WriteJSON(w, http.StatusAccepted, h.current())
}

func (h *Handler) cancel(w http.ResponseWriter, r *http.Request) {
	if !h.Controller.Cancel() {
		httpx.WriteError(w, http.StatusConflict, "not_draining", "no restart is in progress")
		return
	}
	h.record(r, "system.restart_cancel", map[string]any{"live_sessions": h.Controller.Registry.Count()})
	httpx.WriteJSON(w, http.StatusOK, h.current())
}

func (h *Handler) record(r *http.Request, action string, details map[string]any) {
	if h.Audit == nil {
		return
	}
	actor := audit.Actor{IP: auth.ClientIP(r)}
	if p, ok := auth.FromContext(r.Context()); ok {
		actor.UserID = p.User.ID
	}
	if _, err := h.Audit.Record(r.Context(), actor.Event(action, "system", "gateway", audit.Success, details)); err != nil {
		h.Log.Error("audit record failed", "action", action, "err", err)
	}
}
