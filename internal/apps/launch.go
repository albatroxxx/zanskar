// SPDX-License-Identifier: Apache-2.0

package apps

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/access"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/target"
)

const restartingMsg = "the gateway is restarting to apply a configuration change; try again in a minute"

type launchRequest struct {
	// App is the application's label, State the value its host sent the
	// browser to the console with, Next where to land on it afterwards.
	App   string `json:"app"`
	State string `json:"state"`
	Next  string `json:"next"`
}

// launch answers POST /api/v1/me/applications/launch, which the console's
// /launch page calls for a browser an application host sent over: the
// policies decide, as for any target, and the answer is the address on the
// application host that carries the one-time code back. The decision is
// audited as session.connect with protocol http, success or refusal, like a
// ticket's.
func (h *Handler) launch(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	actor := auth.ActorFor(r)
	var in launchRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	in.App = strings.ToLower(strings.TrimSpace(in.App))
	if !target.ValidLabel(in.App) {
		httpx.BadRequest(w, r, "app must be an application's label")
		return
	}
	if !validState(in.State) {
		httpx.BadRequest(w, r, "state must be the value the application's address sent you with")
		return
	}
	deny := func(status int, code, msg, targetID string) {
		h.record(r, actor.Event(audit.SessionConnect, "target", targetID, audit.Failure, map[string]any{"protocol": protocol.HTTP, "reason": code, "label": in.App}))
		httpx.WriteError(w, r, status, code, msg)
	}
	if err := h.Ready(); err != nil {
		httpx.WriteError(w, r, http.StatusConflict, "apps_not_ready", err.Error())
		return
	}
	if h.draining() {
		deny(http.StatusServiceUnavailable, "restarting", restartingMsg, "")
		return
	}
	t, err := h.Targets.GetByLabel(r.Context(), in.App)
	switch {
	case errors.Is(err, target.ErrNotFound):
		deny(http.StatusNotFound, "not_found", "no such application", "")
		return
	case err != nil:
		httpx.Internal(w, r, h.log(), err)
		return
	case !t.IsApplication():
		deny(http.StatusNotFound, "not_found", "no such application", t.ID)
		return
	case t.Status != target.StatusActive:
		deny(http.StatusConflict, "target_disabled", "this application is disabled", t.ID)
		return
	}
	_, code, msg, err := h.Gate.Admit(r.Context(), p.User.ID, policy.TargetRef{ID: t.ID, Tags: t.Tags}, protocol.HTTP, time.Now())
	if err != nil {
		httpx.Internal(w, r, h.log(), err)
		return
	}
	if code != "" {
		deny(codeStatus(code), code, msg, t.ID)
		return
	}
	tok, err := h.store().issue(handoff{AuthSessionID: p.Session.ID, UserID: p.User.ID, TargetID: t.ID, Label: in.App, State: in.State, ClientIP: auth.ClientIP(r)})
	if err != nil {
		httpx.Internal(w, r, h.log(), err)
		return
	}
	h.record(r, actor.Event(audit.SessionConnect, "target", t.ID, audit.Success, map[string]any{"protocol": protocol.HTTP, "label": in.App}))
	q := url.Values{"code": {tok}, "state": {in.State}, "next": {safePath(in.Next)}}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"url": h.origin(in.App) + enterPath + "?" + q.Encode()})
}

// codeStatus is the HTTP status of a gate refusal, as the connect route
// answers the same codes.
func codeStatus(code string) int {
	switch code {
	case access.CodePolicyDenied, access.CodeApprovalRequired, access.CodeMFARequired:
		return http.StatusForbidden
	default:
		return http.StatusConflict
	}
}
