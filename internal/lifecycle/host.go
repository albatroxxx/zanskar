// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
)

// Host actions (ADR 0032). Reboot and power off go through systemctl, which
// asks logind over D-Bus and polkit for leave; the package ships the rule
// that grants the zanskar user exactly those two verbs, so the web process
// never becomes root. Each action drains live sessions first, like a
// restart, and is guarded by an administrator's recent authenticator code,
// the typed hostname, and an audit event written before anything happens.

// stepUpFor is how recent the session's authenticator proof must be.
const stepUpFor = 5 * time.Minute

// hostActionTimeout bounds the systemctl call itself.
const hostActionTimeout = 30 * time.Second

// HostStatus is what the gear reads before offering the actions.
type HostStatus struct {
	Hostname   string `json:"hostname"`
	Supervisor string `json:"supervisor"`
	// Available says the actions can be offered: the gateway runs under
	// systemd. Elsewhere Reason says why not.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// MFAFresh says the session proved an authenticator code within
	// StepUpMinutes; otherwise the console asks for one first.
	MFAFresh      bool `json:"mfa_fresh"`
	StepUpMinutes int  `json:"step_up_minutes"`
}

type hostRequest struct {
	WaitMinutes *int   `json:"wait_minutes"`
	Confirm     string `json:"confirm"`
}

func (h *Handler) supervisor() string {
	if h.Supervisor != nil {
		return h.Supervisor()
	}
	return Supervisor()
}

func (h *Handler) hostname() string {
	if h.Hostname != nil {
		return h.Hostname()
	}
	name, _ := os.Hostname()
	return name
}

func (h *Handler) hostAvailable() (bool, string) {
	if s := h.supervisor(); s != "systemd" {
		return false, "host actions need a systemd host; this gateway runs under " + s
	}
	return true, ""
}

// fresh reports whether the session proved an authenticator code recently
// enough for a host action.
func fresh(p *auth.Principal) bool {
	return p != nil && p.Session != nil && !p.Session.MFAAt.IsZero() && time.Since(p.Session.MFAAt) <= stepUpFor
}

func (h *Handler) host(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	ok, reason := h.hostAvailable()
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, HostStatus{
		Hostname: h.hostname(), Supervisor: h.supervisor(), Available: ok, Reason: reason,
		MFAFresh: fresh(p), StepUpMinutes: int(stepUpFor / time.Minute),
	})
}

func (h *Handler) reboot(w http.ResponseWriter, r *http.Request) {
	h.hostAction(w, r, "reboot", audit.SystemReboot)
}

func (h *Handler) poweroff(w http.ResponseWriter, r *http.Request) {
	h.hostAction(w, r, "poweroff", audit.SystemPowerOff)
}

// hostAction drains, then runs `systemctl <verb>`. The verb doubles as the
// drain's action name. A failed command (polkit refused, no logind) cancels
// the drain so the gateway serves again, and is audited as a failure.
func (h *Handler) hostAction(w http.ResponseWriter, r *http.Request, verb, action string) {
	if ok, reason := h.hostAvailable(); !ok {
		httpx.WriteError(w, r, http.StatusConflict, "unsupported_supervisor", reason)
		return
	}
	p, _ := auth.FromContext(r.Context())
	if !fresh(p) {
		httpx.WriteError(w, r, http.StatusForbidden, "step_up_required", "prove your authenticator first: this action asks for a recent code")
		return
	}
	var in hostRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	name := h.hostname()
	if strings.TrimSpace(in.Confirm) != name {
		httpx.WriteError(w, r, http.StatusBadRequest, "confirm_mismatch", fmt.Sprintf("type the gateway's hostname (%s) to confirm", name))
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
	before := h.current()
	// Audited before acting: a reboot that succeeds leaves no later chance.
	h.record(r, action, map[string]any{"wait_minutes": int(wait / time.Minute), "live_sessions": before.LiveSessions, "hostname": name, "supervisor": before.Supervisor})
	actor := auth.ActorFor(r)
	run := h.Run
	if run == nil {
		run = runCommand
	}
	h.Controller.RestartThen(p.User.ID, wait, verb, func() {
		ctx, cancel := context.WithTimeout(context.Background(), hostActionTimeout)
		defer cancel()
		err := run(ctx, "systemctl", verb)
		if err == nil {
			return
		}
		if h.Log != nil {
			h.Log.Error("host action failed", "action", verb, "err", err)
		}
		if h.Audit != nil {
			_, _ = h.Audit.Record(ctx, actor.Event(action, "system", "gateway", audit.Failure, map[string]any{"hostname": name, "error": err.Error()}))
		}
		h.Controller.Cancel()
	})
	httpx.WriteJSON(w, http.StatusAccepted, h.current())
}

// runCommand runs a fixed command and folds its output into the error.
func runCommand(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- fixed systemctl verbs, never input
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
