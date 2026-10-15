// SPDX-License-Identifier: Apache-2.0

package update

import (
	"log/slog"
	"net/http"

	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Handler serves the bell: the last version check, and a check on demand.
// Both are admin-only reads of public information, so neither is audited.
type Handler struct {
	Checker *Checker
	Log     *slog.Logger
	// StateDir is where the installer reports; Supervisor says whether the
	// console may ask for an install at all (systemd only).
	StateDir   string
	Supervisor func() string
}

func (h *Handler) status() Status {
	s := h.Checker.Status()
	s.Installable = h.StateDir != "" && h.Supervisor != nil && h.Supervisor() == "systemd"
	s.Install = ReadInstallState(h.StateDir)
	return s
}

// Register mounts the routes under the admin system prefix (ADR 0029).
func (h *Handler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/admin/system/update", admin(http.HandlerFunc(h.get)))
	mux.Handle("POST /api/v1/admin/system/update/check", admin(http.HandlerFunc(h.check)))
}

func (h *Handler) get(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, h.status())
}

func (h *Handler) check(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	h.Checker.Check(r.Context())
	httpx.WriteJSON(w, http.StatusOK, h.status())
}
