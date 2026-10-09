// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Handler serves session, recording and audit read endpoints for users,
// admins and auditors (ADR 0006: admins and auditors read; only admins act).
type Handler struct {
	Repo     *Repo
	Audit    *audit.Log
	Registry *gateway.Registry
	Storage  recording.Storage
	Log      *slog.Logger
}

// Register mounts the routes.
func (h *Handler) Register(mux *http.ServeMux) {
	reviewer := auth.RequireRole(user.RoleAdmin, user.RoleAuditor)
	admin := auth.RequireRole(user.RoleAdmin)

	// One's own session history belongs to the user portal, which auditor-only
	// accounts do not have (they review everyone's sessions below instead).
	mux.Handle("GET /api/v1/me/sessions", auth.RequireConnect(http.HandlerFunc(h.mySessions)))

	mux.Handle("GET /api/v1/sessions", reviewer(http.HandlerFunc(h.listSessions)))
	mux.Handle("GET /api/v1/sessions/{id}", reviewer(http.HandlerFunc(h.getSession)))
	mux.Handle("POST /api/v1/sessions/{id}/terminate", admin(http.HandlerFunc(h.terminate)))

	mux.Handle("GET /api/v1/recordings/{id}", reviewer(http.HandlerFunc(h.getRecording)))
	mux.Handle("GET /api/v1/recordings/{id}/stream", reviewer(http.HandlerFunc(h.streamRecording)))
	// Downloads for evidence handling: the raw recording, and for terminal
	// sessions the command transcript. Each is a recorded view and an audit
	// event naming the downloader, like a playback (ADR 0006).
	mux.Handle("GET /api/v1/recordings/{id}/download", reviewer(http.HandlerFunc(h.downloadRecording)))
	mux.Handle("GET /api/v1/recordings/{id}/transcript", reviewer(http.HandlerFunc(h.downloadTranscript)))

	mux.Handle("GET /api/v1/audit/events", reviewer(http.HandlerFunc(h.auditEvents)))
	mux.Handle("GET /api/v1/audit/verify", reviewer(http.HandlerFunc(h.auditVerify)))
	mux.Handle("GET /api/v1/audit/facets", reviewer(http.HandlerFunc(h.auditFacets)))

	mux.Handle("GET /api/v1/admin/retention", admin(http.HandlerFunc(h.getRetention)))
	mux.Handle("PUT /api/v1/admin/retention", admin(http.HandlerFunc(h.setRetention)))
}

func (h *Handler) mySessions(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, cursor := httpx.Paging(r, 50, 200)
	items, next, err := h.Repo.List(r.Context(), Filter{UserID: p.User.ID, Limit: limit, Cursor: cursor})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// Users see their own session metadata, never recording ids (ADR 0006).
	for _, s := range items {
		s.RecordingID = ""
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[*Session]{Items: items, NextCursor: next})
}

func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	limit, cursor := httpx.Paging(r, 50, 500)
	q := r.URL.Query()
	f := Filter{UserID: q.Get("user_id"), Username: q.Get("username"), TargetID: q.Get("target_id"), OpenOnly: q.Get("open") == "true", Limit: limit, Cursor: cursor}
	items, next, err := h.Repo.List(r.Context(), f)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[*Session]{Items: items, NextCursor: next})
}

func (h *Handler) getSession(w http.ResponseWriter, r *http.Request) {
	s, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s)
}

func (h *Handler) terminate(w http.ResponseWriter, r *http.Request) {
	s, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if s.EndedAt != nil {
		httpx.WriteError(w, http.StatusConflict, "already_ended", "session already ended")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if r.ContentLength > 0 {
		if err := httpx.DecodeJSON(r, &body); err != nil {
			httpx.BadRequest(w, err.Error())
			return
		}
	}
	found := h.Registry != nil && h.Registry.Terminate(s.ID)
	if !found {
		// Not live in this process (another gateway, or a crash left it open):
		// close the row so it stops showing as open.
		if err := h.Repo.End(r.Context(), s.ID, EndAdminTerminated); err != nil {
			h.fail(w, r, err)
			return
		}
	}
	p, _ := auth.FromContext(r.Context())
	h.record(r, audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}.Event("session.terminate", "access_session", s.ID, audit.Success,
		map[string]any{"target_user_id": s.UserID, "reason": body.Reason, "was_live_here": found}))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "terminating", "live": found})
}

func (h *Handler) getRecording(w http.ResponseWriter, r *http.Request) {
	rec, err := h.Repo.GetRecording(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// The session tells a reviewer who was on which machine; without it the
	// recording is just an id. Missing session metadata is not an error.
	sess, err := h.Repo.Get(r.Context(), rec.SessionID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, struct {
		*Recording
		Session *Session `json:"session,omitempty"`
	}{rec, sess})
}

// streamRecording sends the raw recording. Every stream is a recorded view
// and an audit event naming the viewer.
func (h *Handler) streamRecording(w http.ResponseWriter, r *http.Request) {
	rec, _, rc, ok := h.openForReview(w, r, "recording.view", nil)
	if !ok {
		return
	}
	defer func() { _ = rc.Close() }()
	ct := "application/octet-stream"
	if rec.Format == "asciicast" {
		ct = "application/x-asciicast; charset=utf-8"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Recording-SHA256", rec.SHA256)
	if rec.SizeBytes > 0 && rec.FinishedAt != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(rec.SizeBytes, 10))
	}
	_, _ = io.Copy(w, rc)
}

// openForReview loads a recording for a reviewer, refuses one that retention
// purged, opens its data, and only then records the view and writes the
// audit event with the given action and details, so a recording whose data
// is gone is not logged as seen. It returns the recording, its session (nil
// when unknown), the open data, which the caller closes, and whether the
// caller may go on; on false the response is already written.
func (h *Handler) openForReview(w http.ResponseWriter, r *http.Request, action string, details map[string]any) (*Recording, *Session, io.ReadCloser, bool) {
	rec, err := h.Repo.GetRecording(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return nil, nil, nil, false
	}
	if rec.PurgedAt != nil {
		httpx.WriteError(w, http.StatusGone, "purged", "this recording was deleted by the retention policy")
		return nil, nil, nil, false
	}
	sess, err := h.Repo.Get(r.Context(), rec.SessionID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		h.fail(w, r, err)
		return nil, nil, nil, false
	}
	rc, err := h.Storage.Open(r.Context(), rec.StorageURI)
	if err != nil {
		h.Log.Error("open recording", "id", rec.ID, "err", err)
		httpx.WriteError(w, http.StatusNotFound, "not_found", "recording data unavailable")
		return nil, nil, nil, false
	}
	p, _ := auth.FromContext(r.Context())
	ip := auth.ClientIP(r)
	if err := h.Repo.RecordView(r.Context(), rec.ID, p.User.ID, ip); err != nil {
		_ = rc.Close()
		h.fail(w, r, err)
		return nil, nil, nil, false
	}
	d := map[string]any{"session_id": rec.SessionID, "format": rec.Format}
	for k, v := range details {
		d[k] = v
	}
	h.record(r, audit.Actor{UserID: p.User.ID, IP: ip}.Event(action, "recording", rec.ID, audit.Success, d))
	return rec, sess, rc, true
}

// downloadName builds the attachment file name from what a reviewer knows
// the session as: user, machine and the recording's short id, in characters
// every filesystem accepts.
func downloadName(rec *Recording, sess *Session, ext string) string {
	parts := []string{}
	if sess != nil {
		if sess.Username != "" {
			parts = append(parts, sess.Username)
		}
		switch {
		case sess.TargetName != "":
			parts = append(parts, sess.TargetName)
		case sess.InstanceID != "":
			parts = append(parts, sess.InstanceID)
		case sess.ASGName != "":
			parts = append(parts, sess.ASGName)
		}
	}
	id := rec.ID
	if len(id) > 8 {
		id = id[:8]
	}
	parts = append(parts, id)
	safe := func(s string) string {
		return strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
				return r
			}
			return '_'
		}, s)
	}
	for i := range parts {
		parts[i] = safe(parts[i])
	}
	return strings.Join(parts, "-") + ext
}

// downloadRecording sends the raw recording as an attachment: the asciicast
// file for a terminal session, the guacd instruction stream for a desktop.
func (h *Handler) downloadRecording(w http.ResponseWriter, r *http.Request) {
	rec, sess, rc, ok := h.openForReview(w, r, "recording.download", map[string]any{"kind": "raw"})
	if !ok {
		return
	}
	defer func() { _ = rc.Close() }()
	ct, ext := "application/octet-stream", ".guac"
	if rec.Format == "asciicast" {
		ct, ext = "application/x-asciicast; charset=utf-8", ".cast"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", `attachment; filename="`+downloadName(rec, sess, ext)+`"`)
	w.Header().Set("X-Recording-SHA256", rec.SHA256)
	if rec.SizeBytes > 0 && rec.FinishedAt != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(rec.SizeBytes, 10))
	}
	_, _ = io.Copy(w, rc)
}

// downloadTranscript sends the command lines of a terminal recording as
// plain text: what an auditor hands to someone who will never open the
// player. Input the remote did not echo appears as "(hidden input)", which
// is all that was ever stored of it.
func (h *Handler) downloadTranscript(w http.ResponseWriter, r *http.Request) {
	rec, err := h.Repo.GetRecording(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if rec.Format != "asciicast" {
		httpx.WriteError(w, http.StatusConflict, "not_a_terminal_recording", "a command transcript exists for terminal sessions only; download the desktop recording instead")
		return
	}
	rec, sess, rc, ok := h.openForReview(w, r, "recording.download", map[string]any{"kind": "transcript"})
	if !ok {
		return
	}
	markers, err := recording.Markers(rc)
	_ = rc.Close()
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var header []string
	if sess != nil {
		where := sess.TargetName
		if where == "" {
			where = strings.TrimSpace(sess.ASGName + " " + sess.InstanceID)
		}
		header = append(header, fmt.Sprintf("%s on %s (%s)", sess.Username, where, strings.ToUpper(sess.Protocol)))
		header = append(header, "started "+sess.StartedAt.UTC().Format(time.RFC3339))
	}
	header = append(header, "recording "+rec.ID, "sha256 "+rec.SHA256, "commands the user submitted; input the remote did not echo is (hidden input) and was never stored")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+downloadName(rec, sess, "-commands.txt")+`"`)
	_ = recording.WriteTranscript(w, header, markers)
}

// auditRow is an audit event as the review UI receives it: the stored record
// plus display names looked up at read time. Names are decoration, not part
// of the hash chain; a deleted user's events keep their id and lose the name.
type auditRow struct {
	audit.Event
	ActorUsername string `json:"actor_username,omitempty"`
	ObjectName    string `json:"object_name,omitempty"`
	// DetailsNames labels the ids inside Details, keyed by the detail key
	// ("target_id" → "web-1"). Read-time decoration only: the stored details
	// and every hashed field stay exactly as written (ADR 0008).
	DetailsNames map[string]string `json:"details_names,omitempty"`
}

// detailNameKinds maps the id-bearing keys audit details use to the object
// kinds ResolveNames knows, tried in order. target_id is tried as a target
// and then as an autoscaling instance, because connect events record the
// live key, which is the instance row id for autoscaling sessions.
var detailNameKinds = map[string][]string{
	"target_id":        {"target", "asg_instance"},
	"asg_id":           {"autoscaling_group"},
	"asg_instance_id":  {"asg_instance"},
	"policy_id":        {"access_policy"},
	"credential_id":    {"credential"},
	"user_id":          {"user"},
	"approver_user_id": {"user"},
	"group_id":         {"group"},
	"recording_id":     {"recording"},
	"session_id":       {"access_session"},
}

// detailIDs collects, per object kind, the ids found under known keys of each
// event's details, and per event the key→id pairs to label afterwards. Details
// are whatever the writer stored; anything that is not an object of string
// values is skipped rather than refused, because the log is never rejected
// for what a row carries.
func detailIDs(items []audit.Event) (map[string][]string, []map[string]string) {
	byKind := map[string][]string{}
	perEvent := make([]map[string]string, len(items))
	for i, e := range items {
		if len(e.Details) == 0 {
			continue
		}
		var d map[string]any
		if err := json.Unmarshal(e.Details, &d); err != nil {
			continue
		}
		for key, kinds := range detailNameKinds {
			id, ok := d[key].(string)
			if !ok || id == "" {
				continue
			}
			if perEvent[i] == nil {
				perEvent[i] = map[string]string{}
			}
			perEvent[i][key] = id
			for _, kind := range kinds {
				byKind[kind] = append(byKind[kind], id)
			}
		}
	}
	return byKind, perEvent
}

var excludeToken = regexp.MustCompile(`^[a-z0-9_.]{1,64}(:(success|failure))?$`)

func (h *Handler) auditEvents(w http.ResponseWriter, r *http.Request) {
	limit, cursor := httpx.Paging(r, 50, 500)
	q := r.URL.Query()
	f := audit.Filter{ActorUserID: q.Get("actor_user_id"), Action: q.Get("action"), ObjectType: q.Get("object_type"), ObjectID: q.Get("object_id"), Cursor: cursor, Limit: limit}
	// Filter by the name a reviewer knows rather than an id. An unknown name
	// matches nothing, not everything.
	if name := strings.TrimSpace(q.Get("actor")); name != "" {
		id, err := h.Repo.UserIDByUsername(r.Context(), name)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if id == "" {
			id = "-"
		}
		f.ActorUserID = id
	}
	for _, ex := range strings.Split(q.Get("exclude"), ",") {
		ex = strings.TrimSpace(ex)
		if ex == "" {
			continue
		}
		if !excludeToken.MatchString(ex) || len(f.Exclude) >= 16 {
			httpx.BadRequest(w, "exclude: expected action or action:outcome tokens")
			return
		}
		f.Exclude = append(f.Exclude, ex)
	}
	if s := q.Get("from"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			f.From = t
		}
	}
	if s := q.Get("to"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			f.To = t
		}
	}
	items, next, err := h.Audit.List(r.Context(), f)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	rows, err := h.decorate(r.Context(), items)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	p, _ := auth.FromContext(r.Context())
	h.record(r, audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}.Event("audit.read", "audit_log", "", audit.Success,
		map[string]any{"count": len(items), "filter_action": f.Action, "filter_actor": f.ActorUserID}))
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[auditRow]{Items: rows, NextCursor: next})
}

// decorate attaches actor usernames and object names to a page of events with
// one lookup per object type. Queries run one after another, never with a
// cursor left open, which the single-connection SQLite setup requires.
func (h *Handler) decorate(ctx context.Context, items []audit.Event) ([]auditRow, error) {
	actorIDs := make([]string, 0, len(items))
	byType := map[string][]string{}
	for _, e := range items {
		actorIDs = append(actorIDs, e.ActorUserID)
		if e.ObjectID != "" {
			byType[e.ObjectType] = append(byType[e.ObjectType], e.ObjectID)
		}
	}
	actors, err := h.Repo.ResolveNames(ctx, "user", actorIDs)
	if err != nil {
		return nil, err
	}
	// Ids named inside details (target_id, policy_id, ...) are resolved with
	// the same per-kind lookups, so a row reads "policy prod-ssh" rather than
	// a hex id even in its expanded form.
	detailKinds, perEvent := detailIDs(items)
	for kind, ids := range detailKinds {
		byType[kind] = append(byType[kind], ids...)
	}
	names := map[string]map[string]string{}
	for kind, ids := range byType {
		m, err := h.Repo.ResolveNames(ctx, kind, ids)
		if err != nil {
			return nil, err
		}
		names[kind] = m
	}
	rows := make([]auditRow, len(items))
	for i, e := range items {
		rows[i] = auditRow{Event: e, ActorUsername: actors[e.ActorUserID], ObjectName: names[e.ObjectType][e.ObjectID]}
		for key, id := range perEvent[i] {
			for _, kind := range detailNameKinds[key] {
				if name, ok := names[kind][id]; ok {
					if rows[i].DetailsNames == nil {
						rows[i].DetailsNames = map[string]string{}
					}
					rows[i].DetailsNames[key] = name
					break
				}
			}
		}
	}
	return rows, nil
}

// auditFacets lists the values the events filter can offer. Like auditVerify it
// records no event of its own: it is part of loading the page whose read is
// already logged, and a second row per page load would only add noise.
func (h *Handler) auditFacets(w http.ResponseWriter, r *http.Request) {
	f, err := h.Audit.Facets(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, f)
}

func (h *Handler) auditVerify(w http.ResponseWriter, r *http.Request) {
	res, err := h.Audit.Verify(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"intact":    res.Broken == nil,
		"checked":   res.Checked,
		"last_id":   res.LastID,
		"last_hash": res.LastHash,
		"broken":    res.Broken,
	})
}

func (h *Handler) record(r *http.Request, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if _, err := h.Audit.Record(r.Context(), e); err != nil {
		h.Log.Error("audit record failed", "action", e.Action, "err", err)
	}
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	h.Log.Error("session handler", "path", r.URL.Path, "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
}

// getRetention returns the current recording-retention policy (admin only).
func (h *Handler) getRetention(w http.ResponseWriter, r *http.Request) {
	p, err := h.Repo.GetRetentionPolicy(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

// setRetention updates the retention policy (admin only) and audits the change.
func (h *Handler) setRetention(w http.ResponseWriter, r *http.Request) {
	var in RetentionPolicy
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if in.MaxAgeDays < 0 || in.MaxTotalBytes < 0 {
		httpx.BadRequest(w, "retention values must not be negative")
		return
	}
	p, _ := auth.FromContext(r.Context())
	if err := h.Repo.SetRetentionPolicy(r.Context(), in, p.User.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}.Event("retention.policy.update", "retention_policy", retentionPolicyID, audit.Success,
		map[string]any{"max_age_days": in.MaxAgeDays, "max_total_bytes": in.MaxTotalBytes}))
	saved, err := h.Repo.GetRetentionPolicy(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, saved)
}
