// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
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
	// For the metrics endpoint: the volumes the gateway writes (either may
	// be empty — a Postgres database, recordings in S3) and where the
	// desktop relay should answer (a runtime setting, read per request).
	DatabasePath   string
	RecordingsPath string
	GuacdAddr      func() string
	cpu            cpuSampler
	// For the host actions (ADR 0032); nil means the real host: systemd
	// detection, os.Hostname, and systemctl.
	Supervisor func() string
	Hostname   func() string
	Run        func(ctx context.Context, name string, args ...string) error
	// StateDir holds the update request the package's path unit watches
	// (ADR 0032); empty disables installing from the console.
	StateDir string
	// installPoll and installLimit pace watchInstall; zero means 2 seconds
	// and installWatchLimit. Tests shorten them.
	installPoll, installLimit time.Duration
}

// Register mounts the routes; all admin-only.
func (h *Handler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/admin/system/status", admin(http.HandlerFunc(h.status)))
	mux.Handle("GET /api/v1/admin/system/metrics", admin(http.HandlerFunc(h.metrics)))
	mux.Handle("GET /api/v1/admin/system/host", admin(http.HandlerFunc(h.host)))
	mux.Handle("POST /api/v1/admin/system/reboot", admin(http.HandlerFunc(h.reboot)))
	mux.Handle("POST /api/v1/admin/system/poweroff", admin(http.HandlerFunc(h.poweroff)))
	mux.Handle("POST /api/v1/admin/system/update/install", admin(http.HandlerFunc(h.installUpdate)))
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
	var rep Report
	if h.Drift != nil {
		rep = h.Drift.Check()
	}
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
			httpx.BadRequest(w, r, err.Error())
			return
		}
	}
	wait := DefaultWait
	if in.WaitMinutes != nil {
		if *in.WaitMinutes < 0 || time.Duration(*in.WaitMinutes)*time.Minute > MaxWait {
			httpx.BadRequest(w, r, "wait_minutes must be between 0 and 240")
			return
		}
		wait = time.Duration(*in.WaitMinutes) * time.Minute
	}
	p, _ := auth.FromContext(r.Context())
	before := h.current()
	d := h.Controller.Restart(p.User.ID, wait)
	h.record(r, audit.SystemRestart, map[string]any{
		"wait_minutes": d.WaitMinutes, "live_sessions": before.LiveSessions,
		"env_file_state": before.EnvFile.State, "changed_env": before.EnvFile.Changed, "supervisor": before.Supervisor,
	})
	httpx.WriteJSON(w, http.StatusAccepted, h.current())
}

func (h *Handler) cancel(w http.ResponseWriter, r *http.Request) {
	if !h.Controller.Cancel() {
		httpx.WriteError(w, r, http.StatusConflict, "not_draining", "no restart is in progress")
		return
	}
	h.record(r, audit.SystemRestartCancel, map[string]any{"live_sessions": h.Controller.Registry.Count()})
	httpx.WriteJSON(w, http.StatusOK, h.current())
}

func (h *Handler) record(r *http.Request, action string, details map[string]any) {
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(action, "system", "gateway", audit.Success, details))
}
