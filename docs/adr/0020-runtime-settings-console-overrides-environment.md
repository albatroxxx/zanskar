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
- The guacd address is now chosen over HTTP as well, and the vaulted RDP or VNC password
  goes to whatever it names, in clear over guacd's own protocol (`internal/connect/desktop.go`
  dials it at each desktop session; the metrics endpoint dials it on each poll to report
  reachability). The same holds for `database.proxy_image` (ADR 0017 addendum), the image
  that receives a vaulted database credential in its environment. An administrator, or a
  stolen administrator session, can therefore receive a credential rather than a session,
  which is residual risk 7 in the threat model (2026-10-26 review, S3-3). Decided
  2026-10-27: they stay runtime, bounded. The console accepts the guacd address only as a
  loopback or private address, or a name resolving to one, and the relay image only pinned
  by `@sha256` digest; setting or resetting either asks for an authenticator code proved in
  the last five minutes (`403 step_up_required`, the host actions' rule, ADR 0032); and the
  guacd dials, for a session and for the metrics check, go through a dialer that refuses an
  address outside that network before a packet is sent, so a name that later resolves
  elsewhere gains nothing. The environment file keeps its freedom: it is root's to edit,
  and the default relay image is named by tag there. The change is audited like any other
  setting; alert on `settings.update` for these two keys.
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

## Amendment (2026-09-29): settings with a secret

Recording storage is the first runtime setting that carries a secret (a static S3 access
key). It follows the same precedence (console over the `ZANSKAR_RECORDINGS_S3_*` install-time
values over the local directory) but lives in its own sealed row rather than the plain
`settings` table, and is only saved after a probe wrote, read back and deleted an object
with it, because a session whose upload fails still leaves a recording row behind. The
active backend is swapped on a router that reads every recording by its own URI, so a
change applies to the next session and earlier recordings stay reachable; a move of local
recordings into the bucket is offered from the same card. The gateway's TLS certificate
(ADR 0021) takes the same shape.

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

## Amendment (2026-10-30): the console edits an allowlist of boot settings, through a root helper

Accepted by the product owner on 2026-10-30, after a walkthrough of the live console: an
administrator who can already restart the gateway from the console should not have to open a
shell to change its public address. The rule above stands for the process: **the gateway
never writes the environment file.** A change is a request that a root helper applies.

- **The request.** An administrator with a fresh authenticator code (the step-up of ADR 0032)
  submits new values for allowlisted keys. The gateway audits `settings.boot_requested` with
  the names and the new values (none of the allowlisted keys holds a secret), writes
  `/var/lib/zanskar/config-request` (JSON, at most 16 KiB), and a path unit the package ships,
  `zanskar-config.path`, starts `zanskar-config.service`. The gateway holds no systemd
  privilege, as for updates.
- **The helper treats the request as hostile.** It runs as root, removes the request first
  (no loop), and refuses the whole request on any key outside the allowlist or any value its
  validator rejects. Values may not contain a newline, NUL, quote or backslash; each key has a
  validator (an `https://` URL without a path, a list of DNS names and IP addresses, an
  integer in range, a printable issuer of at most 64 bytes, an enum). It writes the new file
  beside the old one, `fsync`s it, keeps the old one as `/etc/zanskar/env.previous`, renames
  it into place with the same owner and mode (`root:zanskar 0640`), and writes its answer to
  `/var/lib/zanskar/config-result`, which the console shows.
- **Applying it is the restart we have.** Drift detection already names the changed
  variables, and the banner restarts with a drain.
- **A change that stops the gateway is rolled back.** The service runs `zanskar config check`
  before `serve` (`ExecStartPre`); when it fails right after a helper write (a marker file
  says so), `OnFailure=` restores `env.previous` and starts the service again, and the
  console reports the rollback with the check's reason.
- **The allowlist:**
  - `ZANSKAR_APPS_MAX_SESSIONS` and `ZANSKAR_DATABASE_MAX_SESSIONS`;
  - `ZANSKAR_PUBLIC_URL`;
  - `ZANSKAR_TLS_HOSTS`;
  - `ZANSKAR_LOG_FORMAT`;
  - `ZANSKAR_ISSUER`, with a warning that enrolled authenticators keep the old name;
  - `ZANSKAR_AWS_GATEWAY_PRINCIPAL`;
  - the TLS mode.
- **The TLS mode is a preset, not a free-form edit.** Switching it must change the listen
  address and the proxy trust together, or the gateway would come up unreachable:
  - `proxy` writes `ZANSKAR_TLS_MODE=proxy`, `LISTEN_ADDR=127.0.0.1:8443`,
    `TRUST_PROXY_TLS=true` and no redirect;
  - `managed` writes `ZANSKAR_TLS_MODE=managed`, `LISTEN_ADDR=:443`,
    `HTTP_REDIRECT_ADDR=:80` and `TRUST_PROXY_TLS=false`.
  - The console warns that a proxy still holding those ports must be stopped first. If it is
    not, the rollback catches it.
- **Install-only, with the reason shown beside each in the console:**
  - the database driver and DSN: its credentials, and a different database is a different
    gateway;
  - the master key: it seals every secret, so `zanskar key rotate-master` changes it;
  - the container runtime: any program path would run as the service user;
  - the listen address outside the presets: the console could lock itself out;
  - allow plain HTTP;
  - trusted proxies and proxy TLS trust: they decide which client addresses and cookies are
    believed;
  - the TLS certificate file paths;
  - the recordings directory: a path the service writes anywhere;
  - SIEM export: it would ship the audit stream elsewhere.
- **Systemd package installs only.** Elsewhere, as for host actions, the endpoints answer 409
  `unsupported_supervisor` and the table stays read-only.

A stolen administrator session with a current code can therefore change how the gateway
names itself and how many sessions it runs. It cannot change what the gateway trusts, where it
keeps data, or what it executes.
