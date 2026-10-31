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
	"github.com/albatroxxx/zanskar/internal/idp"
	"github.com/albatroxxx/zanskar/internal/policy"
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
	// Users and Policies give the security posture (2026-10-31); MFAOwners
	// lists the identity providers that are their accounts' second factor.
	Users     *user.Repo
	Policies  *policy.Repo
	MFAOwners func(ctx context.Context) ([]string, error)
	// Chain, Directories and ExportSinks give the integrity row: the
	// background chain check's last result, the identity providers'
	// listings, and the SIEM sinks configured.
	Chain       func() *audit.CheckResult
	Directories func(ctx context.Context) (idp.SyncHealth, error)
	ExportSinks []string
	// Zone is the console's time zone (display.time_zone), whose calendar
	// days the trends count; nil is UTC.
	Zone func() *time.Location
}

// trendDays is how many calendar days the trends cover, today included.
const trendDays = 7

// trends are the last seven calendar days in the console's zone, today
// last and so far: sessions started and connections refused, each day a
// count (2026-10-31). Calendar days, not 24-hour windows from now, so a day
// here is the day the Events page's filter shows.
type trends struct {
	Days     []string `json:"days"`
	Sessions []int    `json:"sessions"`
	Refused  []int    `json:"refused"`
}

// dayBounds are the starts of the last trendDays days in loc, then now:
// trendDays+1 bounds. Each start is built from the date, so a day with a
// daylight-saving change has its true length.
func dayBounds(now time.Time, loc *time.Location) ([]time.Time, []string) {
	local := now.In(loc)
	bounds := make([]time.Time, 0, trendDays+1)
	days := make([]string, 0, trendDays)
	for i := trendDays - 1; i >= 0; i-- {
		d := time.Date(local.Year(), local.Month(), local.Day()-i, 0, 0, 0, 0, loc)
		bounds = append(bounds, d)
		days = append(days, d.Format(time.DateOnly))
	}
	return append(bounds, now), days
}

func (h *Handler) countTrends(ctx context.Context, now time.Time) (trends, error) {
	loc := time.UTC
	if h.Zone != nil {
		if z := h.Zone(); z != nil {
			loc = z
		}
	}
	bounds, days := dayBounds(now, loc)
	t := trends{Days: days}
	var err error
	if t.Sessions, err = h.Sessions.StartedPer(ctx, bounds); err != nil {
		return t, err
	}
	t.Refused, err = h.Audit.CountPer(ctx, audit.SessionConnect, audit.Failure, bounds)
	return t, err
}

// lostWindow is how far back the dashboard counts lost recordings: rarer
// than a refused connection, and worse.
const lostWindow = 7 * 24 * time.Hour

// integrity says whether the evidence is whole: the audit chain at its last
// check (null before the first, never shown as intact), recordings lost in
// the last week, the identity providers' listings, the SIEM export.
type integrity struct {
	AuditChain     *audit.CheckResult `json:"audit_chain"`
	RecordingsLost int64              `json:"recordings_lost_7d"`
	Directories    idp.SyncHealth     `json:"directories"`
	Export         struct {
		Sinks  int   `json:"sinks"`
		Behind int64 `json:"behind"`
	} `json:"export"`
}

func (h *Handler) countIntegrity(ctx context.Context, now time.Time) (integrity, error) {
	var in integrity
	if h.Chain != nil {
		in.AuditChain = h.Chain()
	}
	week, err := h.Audit.TallySince(ctx, now.Add(-lostWindow))
	if err != nil {
		return in, err
	}
	for _, t := range week {
		if t.Action == audit.RecordingLost && t.Outcome == audit.Failure {
			in.RecordingsLost += t.Count
		}
	}
	if h.Directories != nil {
		if in.Directories, err = h.Directories(ctx); err != nil {
			return in, err
		}
	}
	in.Export.Sinks = len(h.ExportSinks)
	in.Export.Behind, err = h.Audit.ExportBehind(ctx, h.ExportSinks)
	return in, err
}

// posture is the dashboard's security posture: counts of what weakens
// access, each a link to the list it counted.
type posture struct {
	StandingNoMFA policy.Exposure `json:"standing_no_mfa"`
	user.Posture
}

func (h *Handler) countPosture(ctx context.Context, now time.Time) (posture, error) {
	var p posture
	var err error
	if p.StandingNoMFA, err = h.Policies.CountStandingNoMFA(ctx); err != nil {
		return p, err
	}
	var owners []string
	if h.MFAOwners != nil {
		if owners, err = h.MFAOwners(ctx); err != nil {
			return p, err
		}
	}
	p.Posture, err = h.Users.CountPosture(ctx, now, owners)
	return p, err
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
	post, err := h.countPosture(ctx, time.Now())
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	integ, err := h.countIntegrity(ctx, time.Now())
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	flight, err := h.Requests.CountInFlight(ctx, time.Now())
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	trend, err := h.countTrends(ctx, time.Now())
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
		Posture         posture                `json:"posture"`
		Integrity       integrity              `json:"integrity"`
		InFlight        access.InFlight        `json:"in_flight"`
		Trends          trends                 `json:"trends"`
	}{sessions, pending, targets, inventory, asgs, foldTallies(tallies), post, integ, flight, trend})
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
