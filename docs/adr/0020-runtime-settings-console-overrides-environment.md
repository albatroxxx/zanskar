# 0020. Runtime settings: the console overrides install-time environment values

Date: 2026-09-29

## Status

Accepted. Extends 0014 (guided install writes the environment file) and 0015 (recording
retention is admin-editable runtime policy).

## Context

ADR 0014 made the environment the server's only configuration source and gave `init`
the job of producing it. That contract is right for what must be known before the
process can start at all: where to listen, which database, the master key, the TLS files.

It is wrong for the settings an administrator changes while the gateway runs. Turning
the log level up to chase a fault, pointing the gateway at a guacd that was just started,
relaxing the authenticator requirement on a throwaway install: each of these required
editing `/etc/zanskar/env` by hand and restarting, which drops every live session, and
the manual QA round (R34) found the Settings page misleading because it said "runtime"
but held one field while the rest lived in a file the console could not see.

The retention policy (ADR 0015) and the login banner already live in the database as
admin-editable rows. The question was whether to keep adding one-off pages and one-off
env-or-database decisions, or to settle the split once.

## Decision

Configuration is split into two kinds by one rule: **can the running process apply it
without restarting?**

- **Boot settings** are read once at start from the environment and nowhere else:
  listen addresses, TLS files, proxy trust, database driver and DSN, master key,
  recordings storage, container runtime, SIEM export, authenticator issuer, log format.
  The console lists them read-only with the variable name to edit and masks secrets (the
  DSN loses its password, the master key is shown only as "set, data-key version N").
  The console never writes the environment file.
- **Runtime settings** are applied live. Each is declared once in `internal/settings`
  with a key, type, default and optional environment variable, and resolves in strict
  precedence: built-in default, then the environment variable (the install-time value
  `init` wrote), then the console row in the `settings` table. The console value wins
  until an administrator resets it, which deletes the row so the environment or the
  default applies again. Every set and reset is audited with the previous and the new
  value, and the API reports where the effective value came from.

The first runtime settings are the login banner, `auth.require_mfa`
(`ZANSKAR_REQUIRE_MFA`), `desktop.guacd_addr` (`ZANSKAR_GUACD_ADDR`) and `log.level`
(`ZANSKAR_LOG_LEVEL`). Consumers do not hold a value copied at start: the sign-in
handlers ask for the requirement at each sign-in, the connect handler reads the guacd
address when a desktop session is opened, and the logger's level is a variable the
setting updates. There is no cache to invalidate and no restart to schedule.

`init` keeps writing those three variables so a fresh install is fully described by its
env file and by `init`'s flags and answer file, as ADR 0014 promised configuration tools.
The environment stays the single source for boot settings and the install-time default
for runtime ones; the database holds only what an administrator changed afterwards.

## Consequences

- The authenticator requirement can now be switched off over HTTP by any administrator,
  where before it took host access to the env file and a restart. The change is audited
  with the previous value and its source, the panel shows it as a console override, and
  the requirement can be reset to the install-time value in one click; deployments that
  must keep it fixed should watch for `settings.update` on `auth.require_mfa` in the
  SIEM feed.
- A setting is either applied live or it needs a restart; the panel says which, so
  "save and hope" goes away. A boot setting sent to the runtime API is refused with the
  variable to edit instead.
- The env file and the console can disagree on a runtime setting, by design: the console
  value is the override, and the panel shows both the effective value and its source.
  A configuration tool that manages the env file and expects it to win must reset the
  console value, or not use the console for that setting.
- Adding a runtime setting is one registry entry plus a consumer that reads through the
  service; the panel, the API, validation and audit come for free. Anything that needs a
  restart to change is added to the boot list, not the registry.

## Amendment (2026-09-29): the console tells when a restart is due, and performs it

The split above leaves one gap: a boot setting edited in the env file does nothing
until someone restarts the service, and nothing told the administrator so. Two
additions close it, on the same rule (the process does not apply boot settings; it
notices and restarts).

- **Drift detection.** `serve` snapshots its `ZANSKAR_*` environment before reading
  anything else and compares it, on each status poll, with the environment file it was
  started from (`ZANSKAR_ENV_FILE`, else `/etc/zanskar/env` when it exists; containers
  usually have none and the check is simply off). The file is parsed with systemd's
  `EnvironmentFile=` rules. The console reports the *names* of the variables that
  differ, never a value: the file holds the master key and the database credentials.
  A changed `ZANSKAR_MASTER_KEY` is called out separately, because a restart after a
  hand edit orphans every stored secret, while one after `zanskar key rotate-master` is
  exactly right. So the running process can read the file, `init` writes it
  `root:zanskar 0640` when the service group exists; the process already holds every
  value in its environment, so this widens nothing.
- **Restart with a drain.** An administrator asks for a restart from the banner; the
  request is audited with the changed names and the live-session count. The gateway
  then refuses new sessions and ticket redemptions (503 `restarting`), waits for live
  sessions to end up to the chosen limit (default 15 minutes, at most 4 hours; zero ends
  them now), ends any that remain with the reason `gateway_restart`, and stops serving.
  It exits 0 and leaves starting the next process to the supervisor: `Restart=always`
  under systemd, the container's restart policy under Docker and Kubernetes. Without a
  supervisor the gateway simply stops; the console says which case it detected. A drain
  can be cancelled until the last moment.
