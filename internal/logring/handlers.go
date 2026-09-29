// SPDX-License-Identifier: Apache-2.0

package logring

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

// API serves the admin log routes.
type API struct {
	Ring  *Ring
	Audit *audit.Log
	Log   *slog.Logger
}

// Register mounts the routes; admin-only.
func (h *API) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/admin/logs", admin(http.HandlerFunc(h.list)))
	mux.Handle("GET /api/v1/admin/logs/download", admin(http.HandlerFunc(h.download)))
}

func (h *API) params(r *http.Request) (slog.Level, string, int, bool) {
	var level slog.Level
	if l := r.URL.Query().Get("level"); l != "" {
		if err := level.UnmarshalText([]byte(strings.ToUpper(l))); err != nil {
			return 0, "", 0, false
		}
	} else {
		level = slog.LevelDebug
	}
	limit := 200
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return 0, "", 0, false
		}
		limit = min(n, h.Ring.Capacity())
	}
	return level, r.URL.Query().Get("q"), limit, true
}

func (h *API) list(w http.ResponseWriter, r *http.Request) {
	level, q, limit, ok := h.params(r)
	if !ok {
		httpx.BadRequest(w, "level must be debug, info, warn or error; limit a positive number")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	items := h.Ring.Snapshot(level, q, limit)
	if items == nil {
		items = []Record{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "capacity": h.Ring.Capacity(), "seen": h.Ring.Seen()})
}

// download sends the whole ring, oldest first, one JSON object per line,
// and records that it happened.
func (h *API) download(w http.ResponseWriter, r *http.Request) {
	items := h.Ring.Snapshot(slog.LevelDebug, "", h.Ring.Capacity())
	if h.Audit != nil {
		p, _ := auth.FromContext(r.Context())
		actor := audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}
		if _, err := h.Audit.Record(r.Context(), actor.Event("logs.download", "logs", "gateway", audit.Success, map[string]any{"lines": len(items)})); err != nil {
			h.Log.Error("audit record failed", "action", "logs.download", "err", err)
		}
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="zanskar-logs.jsonl"`)
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	for i := len(items) - 1; i >= 0; i-- {
		_ = enc.Encode(items[i])
	}
}
