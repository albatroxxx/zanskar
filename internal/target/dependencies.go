// SPDX-License-Identifier: Apache-2.0

package target

import (
	"net/http"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/httpx"
)

// listDependencies is what an application's sessions were refused as
// dependencies (ADR 0037, amended 2026-11-03, later), newest first: the
// console offers each private one to allow. Read only: the relay writes it.
func (h *AdminHandler) listDependencies(w http.ResponseWriter, r *http.Request) {
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	items, err := h.Repo.ListRefusals(r.Context(), t.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// clearDependencies forgets the list, audited; the next session fills it
// again with what is still refused.
func (h *AdminHandler) clearDependencies(w http.ResponseWriter, r *http.Request) {
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.Repo.ClearRefusals(r.Context(), t.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.TargetUpdate, t.ID, audit.Success, map[string]any{"name": t.Name, "dependencies_cleared": true})
	w.WriteHeader(http.StatusNoContent)
}
