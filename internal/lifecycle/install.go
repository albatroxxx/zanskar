// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/update"
	"github.com/albatroxxx/zanskar/internal/version"
)

// Updating from the console (ADR 0032). The gateway never installs anything
// itself: after a drain it writes the wanted version to a request file in
// its state directory, and a root-owned path unit the package ships
// (zanskar-update.path → zanskar-update.service) starts the installer, which
// fetches the release on its own, verifies its signature and provenance,
// installs the package and restarts the service. The installer reports to a
// status file the bell reads back. The gateway holds no systemd privilege
// for any of this; it writes one file in its own directory.

// UpdateRequestFile is what the path unit watches, under the state dir.
const UpdateRequestFile = "update-request"

type installRequest struct {
	hostRequest
	Version string `json:"version"`
}

type updateRequest struct {
	Version     string    `json:"version"`
	RequestedBy string    `json:"requested_by"`
	RequestedAt time.Time `json:"requested_at"`
}

func (h *Handler) installAvailable() (bool, string) {
	if ok, reason := h.hostAvailable(); !ok {
		return false, reason
	}
	if h.StateDir == "" {
		return false, "no state directory is configured for update requests"
	}
	return true, ""
}

// installUpdate answers POST /admin/system/update/install: the same guards
// as a reboot, a version that is newer than the running one, an audit event
// before anything happens, a drain, then the request file.
func (h *Handler) installUpdate(w http.ResponseWriter, r *http.Request) {
	if ok, reason := h.installAvailable(); !ok {
		httpx.WriteError(w, r, http.StatusConflict, "unsupported_supervisor", reason)
		return
	}
	p, _ := auth.FromContext(r.Context())
	if !fresh(p) {
		httpx.WriteError(w, r, http.StatusForbidden, "step_up_required", "prove your authenticator first: this action asks for a recent code")
		return
	}
	var in installRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	// What is logged, audited and written for the installer is the version
	// as the parser rebuilt it, never the request's own text; its charset is
	// fixed to ^\d+\.\d+\.\d+(-[0-9A-Za-z-.]+)?$ (CodeQL #60, go/log-injection,
	// dismissed as a false positive: Canonical cannot return a control char).
	in.Version = update.Canonical(in.Version)
	if in.Version == "" {
		httpx.BadRequest(w, r, "version must look like 1.2.3")
		return
	}
	// The packaged installer accepts release versions only; a prerelease
	// would fail there after every session had been drained (S3-8).
	if strings.Contains(in.Version, "-") {
		httpx.WriteError(w, r, http.StatusBadRequest, "prerelease_refused", fmt.Sprintf("%s is a prerelease; the console installs releases only, install it by hand", in.Version))
		return
	}
	if !update.Newer(version.Version, in.Version) {
		httpx.WriteError(w, r, http.StatusBadRequest, "not_newer", fmt.Sprintf("%s is not newer than the running %s", in.Version, version.Version))
		return
	}
	name, wait, ok := h.confirmAndWait(w, r, in.hostRequest)
	if !ok {
		return
	}
	before := h.current()
	h.record(r, audit.SystemUpdate, map[string]any{"version": in.Version, "from": version.Version, "wait_minutes": int(wait / time.Minute), "live_sessions": before.LiveSessions, "hostname": name})
	actor := auth.ActorFor(r)
	req := updateRequest{Version: in.Version, RequestedBy: p.User.ID, RequestedAt: time.Now().UTC()}
	h.Controller.RestartThen(p.User.ID, wait, "update", func() {
		err := writeRequest(filepath.Join(h.StateDir, UpdateRequestFile), req)
		if err == nil {
			go h.watchInstall(req, actor)
			return
		}
		if h.Log != nil {
			h.Log.Error("update request failed", "version", req.Version, "err", err)
		}
		if h.Audit != nil {
			// The request that asked for this answered minutes ago and its
			// context is gone; the failure is recorded under its own.
			ctx, cancel := context.WithTimeout(context.Background(), hostActionTimeout)
			defer cancel()
			_, _ = h.Audit.Record(ctx, actor.Event(audit.SystemUpdate, "system", "gateway", audit.Failure, map[string]any{"version": req.Version, "error": err.Error()}))
		}
		h.Controller.Cancel()
	})
	httpx.WriteJSON(w, http.StatusAccepted, h.current())
}

// installWatchLimit is how long the gateway waits, draining, for the
// installer to replace it before it gives up and serves again.
const installWatchLimit = 20 * time.Minute

// watchInstall ends the drain when the installer reports that this request
// failed, or reports nothing in time. Until 1.9.0 a failed update (a
// download that did not verify, a package that would not install) left the
// gateway draining, refusing every new session, until an administrator
// cancelled the restart by hand. A successful install restarts the service,
// which ends this process and the watch with it.
func (h *Handler) watchInstall(req updateRequest, actor audit.Actor) {
	poll, limit := h.installPoll, h.installLimit
	if poll <= 0 {
		poll = 2 * time.Second
	}
	if limit <= 0 {
		limit = installWatchLimit
	}
	since := req.RequestedAt.Truncate(time.Second)
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		time.Sleep(poll)
		if d := h.Controller.Current(); d == nil || d.Action != "update" {
			return // cancelled, or replaced by another restart
		}
		st := update.ReadInstallState(h.StateDir)
		if st == nil || st.Version != req.Version || st.State != "failed" {
			continue
		}
		if at, err := time.Parse(time.RFC3339, st.At); err != nil || at.Before(since) {
			continue // a report from an earlier attempt
		}
		h.endFailedInstall(req, actor, st.Message)
		return
	}
	h.endFailedInstall(req, actor, fmt.Sprintf("the installer did not finish within %s", limit))
}

// endFailedInstall records why an update did not happen and lets sessions
// start again.
func (h *Handler) endFailedInstall(req updateRequest, actor audit.Actor, why string) {
	if h.Log != nil {
		h.Log.Error("update failed; serving again", "version", req.Version, "reason", why)
	}
	if h.Audit != nil {
		ctx, cancel := context.WithTimeout(context.Background(), hostActionTimeout)
		defer cancel()
		_, _ = h.Audit.Record(ctx, actor.Event(audit.SystemUpdate, "system", "gateway", audit.Failure, map[string]any{"version": req.Version, "error": why}))
	}
	h.Controller.Cancel()
}

// writeRequest writes the file atomically, so the path unit never reads a
// half-written one.
func writeRequest(path string, req updateRequest) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil { // #nosec G306 -- the installer reads it as root; nothing secret inside
		return err
	}
	return os.Rename(tmp, path)
}
