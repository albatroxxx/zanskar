// SPDX-License-Identifier: Apache-2.0

package apps

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/target"
)

const restartingMsg = "the gateway is restarting to apply a configuration change; try again in a minute"

// launch answers GET /api/v1/me/applications/launch. It is a navigation,
// not a call: the console's /launch page sends the browser here, on the
// console's own origin so the sign-in cookie comes along, after an
// application host sent it over with a state. The policies decide as for any
// target, and the browser goes on to the application host with a one-time
// code, or back to the /launch page with the reason it was refused. The code
// is all that changes hands, and it is useless without the state cookie that
// only this browser holds on the application host. The decision is audited
// as session.connect with protocol http, success or refusal, like a ticket's.
func (h *Handler) launch(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	actor := auth.ActorFor(r)
	q := r.URL.Query()
	app := strings.ToLower(strings.TrimSpace(q.Get("app")))
	state := q.Get("state")
	if !navigation(r) {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", "this address is a page to open in the browser, not a call to make")
		return
	}
	if !target.ValidLabel(app) {
		httpx.BadRequest(w, r, "app must be an application's label")
		return
	}
	if !validState(state) {
		httpx.BadRequest(w, r, "state must be the value the application's address sent you with")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	// deny sends the browser back to the console's page with the reason;
	// the label is named only once the application is known, from its row.
	deny := func(code string, t *target.Target) {
		id, back := "", url.Values{"error": {code}}
		if t != nil {
			id, back["app"] = t.ID, []string{t.AppLabel}
		}
		h.record(r, actor.Event(audit.SessionConnect, "target", id, audit.Failure, map[string]any{"protocol": protocol.HTTP, "reason": code, "label": app}))
		http.Redirect(w, r, LaunchPath+"?"+back.Encode(), http.StatusSeeOther)
	}
	if err := h.Ready(); err != nil {
		deny("apps_not_ready", nil)
		return
	}
	if h.draining() {
		deny("restarting", nil)
		return
	}
	t, err := h.Targets.GetByLabel(r.Context(), app)
	switch {
	case errors.Is(err, target.ErrNotFound):
		deny("not_found", nil)
		return
	case err != nil:
		httpx.Internal(w, r, h.log(), err)
		return
	case !t.IsApplication():
		deny("not_found", nil)
		return
	case t.Status != target.StatusActive:
		deny("target_disabled", t)
		return
	}
	_, code, _, err := h.Gate.Admit(r.Context(), p.User.ID, policy.TargetRef{ID: t.ID, Tags: t.Tags}, protocol.HTTP, time.Now())
	if err != nil {
		httpx.Internal(w, r, h.log(), err)
		return
	}
	if code != "" {
		deny(code, t)
		return
	}
	// The path to land on travels with the code, never in the address the
	// application host redeems, so that host redirects only to what the
	// console decided.
	tok, err := h.store().issue(handoff{AuthSessionID: p.Session.ID, UserID: p.User.ID, TargetID: t.ID, Label: t.AppLabel, State: state, ClientIP: auth.ClientIP(r), Next: safePath(q.Get("next"))})
	if err != nil {
		httpx.Internal(w, r, h.log(), err)
		return
	}
	h.record(r, actor.Event(audit.SessionConnect, "target", t.ID, audit.Success, map[string]any{"protocol": protocol.HTTP, "label": t.AppLabel}))
	// The host is the application's own label from its row under the apps
	// domain, never the request's text; the state passed validState and
	// travels in the query, where it names no host.
	// #nosec G710 -- see above
	http.Redirect(w, r, h.origin(t.AppLabel)+enterPath+"?"+url.Values{"code": {tok}, "state": {state}}.Encode(), http.StatusSeeOther)
}
