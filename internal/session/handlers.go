// SPDX-License-Identifier: Apache-2.0

package session

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
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

	mux.Handle("GET /api/v1/me/sessions", auth.RequireAuth(http.HandlerFunc(h.mySessions)))

	mux.Handle("GET /api/v1/sessions", reviewer(http.HandlerFunc(h.listSessions)))
	mux.Handle("GET /api/v1/sessions/{id}", reviewer(http.HandlerFunc(h.getSession)))
	mux.Handle("POST /api/v1/sessions/{id}/terminate", admin(http.HandlerFunc(h.terminate)))

	mux.Handle("GET /api/v1/recordings/{id}", reviewer(http.HandlerFunc(h.getRecording)))
	mux.Handle("GET /api/v1/recordings/{id}/stream", reviewer(http.HandlerFunc(h.streamRecording)))

	mux.Handle("GET /api/v1/audit/events", reviewer(http.HandlerFunc(h.auditEvents)))
	mux.Handle("GET /api/v1/audit/verify", reviewer(http.HandlerFunc(h.auditVerify)))
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
	f := Filter{UserID: q.Get("user_id"), TargetID: q.Get("target_id"), OpenOnly: q.Get("open") == "true", Limit: limit, Cursor: cursor}
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
	httpx.WriteJSON(w, http.StatusOK, rec)
}

// streamRecording sends the raw recording. Every stream is a recorded view
// and an audit event naming the viewer.
func (h *Handler) streamRecording(w http.ResponseWriter, r *http.Request) {
	rec, err := h.Repo.GetRecording(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	p, _ := auth.FromContext(r.Context())
	ip := auth.ClientIP(r)
	if err := h.Repo.RecordView(r.Context(), rec.ID, p.User.ID, ip); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.Actor{UserID: p.User.ID, IP: ip}.Event("recording.view", "recording", rec.ID, audit.Success,
		map[string]any{"session_id": rec.SessionID, "format": rec.Format}))
	rc, err := h.Storage.Open(r.Context(), rec.StorageURI)
	if err != nil {
		h.Log.Error("open recording", "id", rec.ID, "err", err)
		httpx.WriteError(w, http.StatusNotFound, "not_found", "recording data unavailable")
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

func (h *Handler) auditEvents(w http.ResponseWriter, r *http.Request) {
	limit, cursor := httpx.Paging(r, 50, 500)
	q := r.URL.Query()
	f := audit.Filter{ActorUserID: q.Get("actor_user_id"), Action: q.Get("action"), ObjectType: q.Get("object_type"), ObjectID: q.Get("object_id"), Cursor: cursor, Limit: limit}
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
	p, _ := auth.FromContext(r.Context())
	h.record(r, audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}.Event("audit.read", "audit_log", "", audit.Success,
		map[string]any{"count": len(items), "filter_action": f.Action, "filter_actor": f.ActorUserID}))
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[audit.Event]{Items: items, NextCursor: next})
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
