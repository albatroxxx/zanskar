// SPDX-License-Identifier: Apache-2.0

// Package overview serves the numbers the dashboards show (ADR 0029): one
// read-only endpoint per reviewing role, each returning counts computed under
// that role, never row data. Counts are not content, so reading an overview
// records no audit event — the line ADR 0029 draws — and anything on a
// dashboard that lists rows loads through the existing audited endpoints.
package overview

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/albatroxxx/zanskar/internal/access"
	"github.com/albatroxxx/zanskar/internal/asg"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

// window is how far back the "last 24 hours" tallies look.
const window = 24 * time.Hour

// Handler answers the dashboard overviews from the domain repositories.
type Handler struct {
	Sessions *session.Repo
	Requests *access.Repo
	Targets  *target.Repo
	ASGs     *asg.Repo
	Audit    *audit.Log
	Log      *slog.Logger
}

// asgInventory is the autoscaling slice of the admin inventory: enrolled
// groups and their live instances, healthy counted the way the Autoscaling
// page counts them.
type asgInventory struct {
	Groups           int `json:"groups"`
	Instances        int `json:"instances"`
	HealthyInstances int `json:"healthy_instances"`
}

func (h *Handler) countASGs(ctx context.Context) (asgInventory, error) {
	var inv asgInventory
	groups, err := h.ASGs.List(ctx, false)
	if err != nil {
		return inv, err
	}
	inv.Groups = len(groups)
	for _, g := range groups {
		rows, err := h.ASGs.Instances(ctx, g.ID, false)
		if err != nil {
			return inv, err
		}
		for _, in := range rows {
			if in.TerminatedAt != nil {
				continue
			}
			inv.Instances++
			if in.Healthy {
				inv.HealthyInstances++
			}
		}
	}
	return inv, nil
}

// Register mounts the overviews under their portal's API prefix, so a reverse
// proxy rule that scopes a portal's path covers its data too (ADR 0029).
func (h *Handler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	reviewer := auth.RequireRole(user.RoleAdmin, user.RoleAuditor)
	mux.Handle("GET /api/v1/admin/overview", admin(http.HandlerFunc(h.adminOverview)))
	mux.Handle("GET /api/v1/audit/overview", reviewer(http.HandlerFunc(h.auditOverview)))
}

// auditTallies is the 24-hour slice of the audit log both dashboards read,
// folded from one grouped count query.
type auditTallies struct {
	Events          int64 `json:"events"`
	Failures        int64 `json:"failures"`
	FailedLogins    int64 `json:"failed_logins"`
	RefusedConnects int64 `json:"refused_connects"`
}

func foldTallies(ts []audit.Tally) auditTallies {
	var a auditTallies
	for _, t := range ts {
		a.Events += t.Count
		if t.Outcome != audit.Failure {
			continue
		}
		a.Failures += t.Count
		switch t.Action {
		case audit.UserLogin:
			a.FailedLogins += t.Count
		case audit.SessionConnect:
			a.RefusedConnects += t.Count
		}
	}
	return a
}

// reviewTallies is what reviewers did with recordings in the window; it
// counts evidence handling, which is itself audited, so the numbers come from
// the same log.
type reviewTallies struct {
	RecordingViews     int64 `json:"recording_views"`
	RecordingDownloads int64 `json:"recording_downloads"`
}

func foldReviews(ts []audit.Tally) reviewTallies {
	var rv reviewTallies
	for _, t := range ts {
		if t.Outcome != audit.Success {
			continue
		}
		switch t.Action {
		case audit.RecordingView:
			rv.RecordingViews += t.Count
		case audit.RecordingDownload:
			rv.RecordingDownloads += t.Count
		}
	}
	return rv
}

// adminOverview answers GET /api/v1/admin/overview. The queries run one after
// another, never alongside an open cursor (single-connection SQLite).
func (h *Handler) adminOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	since := time.Now().Add(-window)
	sessions, err := h.Sessions.Count(ctx, since)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	pending, err := h.Requests.CountPending(ctx)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	targets, err := h.Targets.CountAttention(ctx)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	inventory, err := h.Targets.CountInventory(ctx)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	asgs, err := h.countASGs(ctx)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	tallies, err := h.Audit.TallySince(ctx, since)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, struct {
		Sessions        session.Counts         `json:"sessions"`
		PendingRequests int                    `json:"pending_requests"`
		Targets         target.AttentionCounts `json:"targets"`
		Inventory       target.Inventory       `json:"inventory"`
		Autoscaling     asgInventory           `json:"autoscaling"`
		Audit           auditTallies           `json:"audit_24h"`
	}{sessions, pending, targets, inventory, asgs, foldTallies(tallies)})
}

// auditOverview answers GET /api/v1/audit/overview for admins and auditors.
func (h *Handler) auditOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	since := time.Now().Add(-window)
	sessions, err := h.Sessions.Count(ctx, since)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	tallies, err := h.Audit.TallySince(ctx, since)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, struct {
		Sessions session.Counts `json:"sessions"`
		Events   auditTallies   `json:"events_24h"`
		Reviews  reviewTallies  `json:"reviews_24h"`
	}{sessions, foldTallies(tallies), foldReviews(tallies)})
}
