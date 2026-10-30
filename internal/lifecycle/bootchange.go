// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/bootedit"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/store"
)

// bootChangeRequest is the console's ask: new values for allowlisted
// variables, or a TLS preset, and how long live sessions may finish.
type bootChangeRequest struct {
	Values      map[string]string `json:"values"`
	TLSMode     string            `json:"tls_mode"`
	WaitMinutes *int              `json:"wait_minutes"`
}

// configWatchLimit is how long the gateway waits, draining, for the helper
// to answer before it serves again.
const configWatchLimit = 10 * time.Minute

// bootChange answers POST /admin/settings/boot (ADR 0020, amended
// 2026-10-30): the guards of a host action, the same checks the root helper
// makes (so a change it would refuse is refused here, at once), an audit
// event before anything happens, a drain, then the request file a path unit
// hands to `zanskar config apply`. The gateway never writes the environment
// file itself.
func (h *Handler) bootChange(w http.ResponseWriter, r *http.Request) {
	if ok, reason := h.installAvailable(); !ok {
		httpx.WriteError(w, r, http.StatusConflict, "unsupported_supervisor", reason)
		return
	}
	p, _ := auth.FromContext(r.Context())
	if !fresh(p) {
		httpx.WriteError(w, r, http.StatusForbidden, "step_up_required", "prove your authenticator first: this action asks for a recent code")
		return
	}
	var in bootChangeRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	req := bootedit.Request{ID: store.NewID(), RequestedBy: p.User.ID, RequestedAt: time.Now().UTC(), Values: in.Values, TLSMode: in.TLSMode}
	changes, err := bootedit.Changes(req)
	if err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_change", err.Error())
		return
	}
	wait := DefaultWait
	if in.WaitMinutes != nil {
		if *in.WaitMinutes < 0 || time.Duration(*in.WaitMinutes)*time.Minute > MaxWait {
			httpx.BadRequest(w, r, "wait_minutes must be between 0 and 240")
			return
		}
		wait = time.Duration(*in.WaitMinutes) * time.Minute
	}
	// None of the allowlisted variables holds a secret, so the values are
	// part of the record.
	h.record(r, audit.SettingsBootRequest, map[string]any{"request_id": req.ID, "changes": changes, "tls_mode": req.TLSMode, "wait_minutes": int(wait / time.Minute), "live_sessions": h.current().LiveSessions})
	actor := auth.ActorFor(r)
	h.Controller.RestartThen(p.User.ID, wait, "config", func() {
		err := writeJSONFile(filepath.Join(h.StateDir, bootedit.RequestFile), req)
		if err == nil {
			go h.watchConfig(req, actor)
			return
		}
		h.endConfig(req, actor, "the request could not be written: "+err.Error())
	})
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"id": req.ID, "status": h.current()})
}

// bootResult answers GET /admin/settings/boot/result: the helper's last
// answer, for the console's progress view.
func (h *Handler) bootResult(w http.ResponseWriter, r *http.Request) {
	res, err := readConfigResult(h.StateDir)
	if err != nil {
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "no change has been applied yet")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, res)
}

// watchConfig ends the drain when the helper refused this request or never
// answered: a change that applies restarts the service, which ends this
// process and the watch with it.
func (h *Handler) watchConfig(req bootedit.Request, actor audit.Actor) {
	poll, limit := h.installPoll, h.installLimit
	if poll <= 0 {
		poll = 2 * time.Second
	}
	if limit <= 0 {
		limit = configWatchLimit
	}
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		time.Sleep(poll)
		if d := h.Controller.Current(); d == nil || d.Action != "config" {
			return
		}
		res, err := readConfigResult(h.StateDir)
		if err != nil || res.ID != req.ID {
			continue
		}
		if res.State == bootedit.Refused {
			h.endConfig(req, actor, res.Message)
			return
		}
	}
	h.endConfig(req, actor, fmt.Sprintf("the helper did not answer within %s; is zanskar-config.path enabled?", limit))
}

// endConfig records why a change did not happen and lets sessions start
// again.
func (h *Handler) endConfig(req bootedit.Request, actor audit.Actor, why string) {
	if h.Log != nil {
		h.Log.Error("install settings not changed; serving again", "request_id", req.ID, "reason", why)
	}
	if h.Audit != nil {
		ctx, cancel := context.WithTimeout(context.Background(), hostActionTimeout)
		defer cancel()
		_, _ = h.Audit.Record(ctx, actor.Event(audit.SettingsBootApply, "system", "gateway", audit.Failure, map[string]any{"request_id": req.ID, "error": why}))
	}
	h.Controller.Cancel()
}

// AckConfigResult audits, once, how the helper's last change ended: it
// restarts the gateway, so the process that asked for it never sees the
// outcome. serve calls it at start.
func AckConfigResult(ctx context.Context, stateDir string, log *audit.Log) {
	res, err := readConfigResult(stateDir)
	if err != nil || res.Acknowledged || res.State == bootedit.Refused || log == nil {
		return
	}
	outcome := audit.Success
	if res.State != bootedit.Applied {
		outcome = audit.Failure
	}
	details := map[string]any{"request_id": res.ID, "state": res.State, "changed": res.Changed}
	if res.Message != "" {
		details["message"] = res.Message
	}
	actor := ""
	if idRe.MatchString(res.RequestedBy) {
		actor = res.RequestedBy
	}
	if _, err := log.Record(ctx, audit.Event{ActorUserID: actor, Action: audit.SettingsBootApply, ObjectType: "system", ObjectID: "gateway", Outcome: outcome, Details: mustJSON(details)}); err != nil {
		return
	}
	res.Acknowledged = true
	_ = writeJSONFile(filepath.Join(stateDir, bootedit.ResultFile), res)
}

// idRe is a user id as store.NewID makes them.
var idRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

func readConfigResult(stateDir string) (bootedit.Result, error) {
	if stateDir == "" {
		return bootedit.Result{}, errors.New("no state directory")
	}
	b, err := os.ReadFile(filepath.Join(stateDir, bootedit.ResultFile)) // #nosec G304 -- a fixed name under the state directory
	if err != nil {
		return bootedit.Result{}, err
	}
	var res bootedit.Result
	if err := json.Unmarshal(b, &res); err != nil {
		return bootedit.Result{}, err
	}
	if !slices.Contains([]string{bootedit.Applied, bootedit.Refused, bootedit.RolledBack}, res.State) {
		return bootedit.Result{}, errors.New("unknown result state")
	}
	return res, nil
}

// writeJSONFile writes v atomically, readable by the root helper.
func writeJSONFile(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil { // #nosec G306 -- read by the root helper; no secret inside
		return err
	}
	return os.Rename(tmp, path)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
