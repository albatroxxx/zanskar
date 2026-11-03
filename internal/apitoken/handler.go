// SPDX-License-Identifier: Apache-2.0

package apitoken

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Limits on a token: how long it may live, the default, and how many an
// administrator may hold at once.
const (
	MaxDays     = 365
	DefaultDays = 90
	MaxActive   = 20
)

// Handler serves /api/v1/admin/api-tokens to administrators signed in with a
// browser; a token reaches none of these routes (auth.TokenAllowed), so a
// token cannot make another.
type Handler struct {
	Repo  *Repo
	Audit *audit.Log
	Log   *slog.Logger
	// MFAEnrolled reports whether a user has a confirmed authenticator: one
	// who has proves a code from the last 5 minutes to make a token, a
	// credential that skips the second factor. nil asks every maker.
	MFAEnrolled func(ctx context.Context, userID string) (bool, error)
}

// Register mounts the routes.
func (h *Handler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/admin/api-tokens", admin(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/v1/admin/api-tokens", admin(http.HandlerFunc(h.create)))
	mux.Handle("DELETE /api/v1/admin/api-tokens/{id}", admin(http.HandlerFunc(h.revoke)))
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	ts, err := h.Repo.List(r.Context())
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[*Token]{Items: ts})
}

type createInput struct {
	Name string `json:"name"`
	Days int    `json:"days"`
}

// created is the answer to a create: the token, and its secret, once.
type created struct {
	*Token
	Secret string `json:"secret"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	var in createInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > 100 {
		httpx.BadRequest(w, r, "name: 1 to 100 characters, saying what the token is for")
		return
	}
	if in.Days == 0 {
		in.Days = DefaultDays
	}
	if in.Days < 1 || in.Days > MaxDays {
		httpx.BadRequest(w, r, fmt.Sprintf("days: 1 to %d", MaxDays))
		return
	}
	if !h.steppedUp(w, r, p) {
		return
	}
	n, err := h.Repo.CountActive(r.Context(), p.User.ID)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	if n >= MaxActive {
		httpx.WriteError(w, r, http.StatusConflict, "too_many_tokens", fmt.Sprintf("you hold %d active tokens, the most there may be; revoke one first", n))
		return
	}
	t, secret, err := h.Repo.Create(r.Context(), p.User.ID, in.Name, time.Duration(in.Days)*24*time.Hour)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	t.Username = p.User.Username
	h.record(r, audit.APITokenCreate, t)
	httpx.WriteJSON(w, http.StatusCreated, created{Token: t, Secret: secret})
}

// steppedUp asks an administrator who has an authenticator for a code from
// the last 5 minutes before making a token, which then acts without one
// (403 step_up_required, as for host actions and approvals).
func (h *Handler) steppedUp(w http.ResponseWriter, r *http.Request, p *auth.Principal) bool {
	if p.StepUpFresh() {
		return true
	}
	if h.MFAEnrolled != nil {
		has, err := h.MFAEnrolled(r.Context(), p.User.ID)
		if err != nil {
			httpx.Internal(w, r, h.Log, err)
			return false
		}
		if !has {
			return true
		}
	}
	httpx.WriteError(w, r, http.StatusForbidden, "step_up_required", "prove your authenticator first: an API token acts without a second factor, so making one asks for a recent code")
	return false
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	cur, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrNotFound) {
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "no such token")
		return
	}
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	t, err := h.Repo.Revoke(r.Context(), cur.ID)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	if cur.RevokedAt == nil {
		h.record(r, audit.APITokenRevoke, t)
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

// record audits a token's making or ending: its name, owner, prefix and
// expiry, never its secret.
func (h *Handler) record(r *http.Request, action string, t *Token) {
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(action, "api_token", t.ID, audit.Success,
		map[string]any{"name": t.Name, "owner_user_id": t.UserID, "prefix": t.Prefix, "expires_at": t.ExpiresAt.UTC().Format(time.RFC3339)}))
}
