// SPDX-License-Identifier: Apache-2.0

package session

import (
	"encoding/json"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
)

// activityRow is one event of a person's own activity: what happened, when,
// from where, and who did it when it was not them. Only the words a person
// needs from the details are kept (activityDetailKeys); the full event is
// the reviewers' (ADR 0006).
type activityRow struct {
	ID         int64          `json:"id"`
	Timestamp  time.Time      `json:"ts"`
	Action     string         `json:"action"`
	Outcome    audit.Outcome  `json:"outcome"`
	IP         string         `json:"ip"`
	By         string         `json:"by,omitempty"`
	ObjectType string         `json:"object_type,omitempty"`
	ObjectName string         `json:"object_name,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

// activityDetailKeys are the details a person's own activity shows: why
// something failed or ended, over what, through which provider.
var activityDetailKeys = []string{"reason", "protocol", "detail", "idp", "method", "duration_minutes"}

// activityRoutine are left out of a person's activity, as the Events page
// leaves them out by default: the reads of the log, and the ticket issued
// before every session (the session itself is listed).
var activityRoutine = []string{audit.AuditRead, audit.SessionConnect + ":success"}

// activityOwn are the actions a person's activity lists of what they did
// themselves: what they do as a user of the access portal. What an
// administrator does in the admin portal (enrolling a target, changing a
// policy) is the Events page's, not their own activity's (2026-11-03,
// later); what another administrator or the gateway did to the person's
// account is listed whatever the action.
var activityOwn = []string{
	audit.UserLogin, audit.UserLogout, audit.UserMFAEnroll, audit.UserMFAConfirm, audit.UserMFAVerify, audit.UserPasswordChange,
	audit.SessionConnect, audit.SessionStart, audit.SessionEnd, audit.SessionFailover,
	audit.AccessRequestCreate,
}

// passwordStage is the first step of a two-step sign-in, which the Events
// page hides as routine: a person's activity lists each sign-in once, at
// its end, not twice a second apart (live, 2026-11-03).
func passwordStage(e audit.Event) bool {
	if e.Action != audit.UserLogin || e.Outcome != audit.Success || len(e.Details) == 0 {
		return false
	}
	var d struct {
		Stage string `json:"stage"`
	}
	return json.Unmarshal(e.Details, &d) == nil && d.Stage == "password"
}

// myActivity answers GET /api/v1/me/activity: the caller's own events,
// newest first, a page at a time (2026-11-03, idea 11). Their sign-ins,
// failed ones too, from where; their sessions and requests; and what an
// administrator or the gateway did to their account, by whom. A person who
// sees a sign-in they did not make knows to say so. Reading one's own
// activity records no event: it shows nobody else's.
func (h *Handler) myActivity(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, cursor := httpx.Paging(r, 50, 200)
	items, next, err := h.Audit.List(r.Context(), audit.Filter{Subject: p.User.ID, OwnActions: activityOwn, Exclude: activityRoutine, Cursor: cursor, Limit: limit})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	items = slices.DeleteFunc(items, passwordStage)
	rows, err := h.decorate(r.Context(), items)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := make([]activityRow, len(rows))
	for i, e := range rows {
		row := activityRow{ID: e.ID, Timestamp: e.Timestamp, Action: e.Action, Outcome: e.Outcome, IP: e.ActorIP, ObjectType: e.ObjectType, ObjectName: e.ObjectName}
		switch {
		case e.ActorUserID == p.User.ID:
		case e.ActorUserID == "":
			row.By = "gateway"
		case e.ActorUsername != "":
			row.By = e.ActorUsername
		default:
			row.By = "deleted user"
		}
		// Another person's address is theirs, not this person's to see. An
		// attempt on this account by nobody signed in (a failed sign-in)
		// keeps where it came from: that is what its owner needs to know.
		if e.ActorUserID != "" && e.ActorUserID != p.User.ID || net.ParseIP(row.IP) == nil {
			row.IP = ""
		}
		var d map[string]any
		if json.Unmarshal(e.Details, &d) == nil {
			for _, k := range activityDetailKeys {
				if v, ok := d[k]; ok {
					if row.Details == nil {
						row.Details = map[string]any{}
					}
					row.Details[k] = v
				}
			}
		}
		out[i] = row
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[activityRow]{Items: out, NextCursor: next})
}
