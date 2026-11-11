// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/bootedit"
	"github.com/albatroxxx/zanskar/internal/states"
)

// DrainLifecycle is the restart drain's declared lifecycle (ADR 0032, ADR
// 0047): the gateway refuses new sessions, waits for the live ones or the
// deadline, ends them, and then restarts, reboots, powers off, installs an
// update or applies install-time settings.
var DrainLifecycle = states.New("restart drain",
	[]string{"idle", "draining", "ended sessions", "exited"},
	states.Move{From: "idle", To: "draining", By: audit.SystemRestart + ", " + audit.SystemReboot + ", " + audit.SystemPowerOff + ", " + audit.SystemUpdate + " or " + audit.SettingsBootRequest},
	states.Move{From: "draining", To: "draining", By: "another request replaces the drain and its action (no event for the one dropped)"},
	states.Move{From: "draining", To: "idle", By: audit.SystemRestartCancel + "; a host command or the request file failing"},
	states.Move{From: "draining", To: "ended sessions", By: "the live sessions end, or the deadline passes (gateway_restart)"},
	states.Move{From: "ended sessions", To: "exited", By: "the bridges close (30 s grace); the process exits or the host acts"},
).Describe(states.Doc{
	Derivation: "`SystemStatus.draining` with `drain{requested_at, deadline, wait_minutes, action}`; `idle` is the field absent. In memory only: a restart forgets it.",
	Notes: []string{
		"The completion of a restart, reboot, power-off or update is never audited; the console infers it from a new `started_at`.",
		"\"Cancel restart\" cancels any drain, whatever its action.",
	},
})

// EnvFileLifecycle is the environment file's drift: whether the file on disk
// still says what the process started with (\"Restart required\").
var EnvFileLifecycle = states.New("environment file",
	[]string{FileUnchanged, FileChanged, FileMissing, FileUnreadable, FileNone},
	states.Move{From: FileUnchanged, To: FileChanged, By: "the file is edited (any variable differs, either way)"},
	states.Move{From: FileChanged, To: FileUnchanged, By: "the edit is undone, or the process restarts and reads the file"},
	states.Move{From: FileUnchanged, To: FileMissing, By: "the file is removed"},
	states.Move{From: FileUnchanged, To: FileUnreadable, By: "the service user may no longer read it, or it does not parse"},
).Describe(states.Doc{
	Field:      "state",
	Schemas:    []string{"EnvFileReport"},
	Derivation: "Diffed on each status read against the environment the process started with (secrets as digests), cached on the file's size and mtime. `restart_required` is `state == changed`.",
	Notes: []string{
		"`none`: no path is configured or found (a container whose environment came from elsewhere).",
	},
})

// BootChangeLifecycle is an install-time settings change made through the
// root helper (ADR 0020, amended).
var BootChangeLifecycle = states.New("install settings change",
	[]string{"requested", "written", bootedit.Applied, bootedit.Refused, bootedit.RolledBack},
	states.Move{From: "requested", To: "written", By: audit.SettingsBootRequest + "; after the drain the request file is written for the helper"},
	states.Move{From: "written", To: bootedit.Refused, By: audit.SettingsBootApply + " (failure): the helper refused it, or did not answer within 10 min"},
	states.Move{From: "written", To: bootedit.Applied, By: audit.SettingsBootApply + " by the next process, which came back with the new file"},
	states.Move{From: "written", To: bootedit.RolledBack, By: audit.SettingsBootApply + " (failure) by the next process: the previous file is back"},
).Describe(states.Doc{
	Derivation: "`ConfigResult.state` is the helper's result file (`applied`, `refused`, `rolled_back`), read back by `GET /admin/settings/boot/result` and matched to the request id; `requested` and `written` are phases of the drain.",
	Notes: []string{
		"The result file is a singleton that never expires: every reader compares the request id.",
	},
})

// InstallLifecycle is the installer's run (ADR 0032): the shell script's
// report in update-status.json.
var InstallLifecycle = states.New("installer run",
	[]string{"requested", "running", "done", "failed"},
	states.Move{From: "requested", To: "running", By: audit.SystemUpdate + "; after the drain the request file is written and the installer starts"},
	states.Move{From: "running", To: "done", By: "the package installed and the service restarted"},
	states.Move{From: "running", To: "failed", By: "the installer failed, or the service did not restart; or no report within 20 min (" + audit.SystemUpdate + " failure)"},
).Describe(states.Doc{
	Derivation: "`UpdateStatus.install.state` is the installer's last report (`running`, `done`, `failed`), kept until the next run; `requested` is the drain.",
	Notes: []string{
		"The words are written by a shell script and read by Go, the console and the OpenAPI enum; nothing shares them.",
	},
})
