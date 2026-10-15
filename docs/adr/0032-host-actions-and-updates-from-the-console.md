# 0032. Host actions and updates from the console, through systemd and polkit

Date: 2026-10-15

## Status

Accepted.

## Context

Administrators want two things from the console's corner: a gear that can restart the
gateway, reboot or stop the machine it runs on, and a bell that says when a newer Zanskar
exists and installs it on the spot.

The gateway runs as the unprivileged `zanskar` user under systemd with `NoNewPrivileges`
and `ProtectSystem=strict` (deploy/packaging/zanskar.service). That is correct and stays:
the web process must never be able to become root, so none of this can be a `sudo` from
the handler. ADR 0027 drew the line that the console is never a way to get the host; this
ADR adds a few named, bounded host actions without crossing it.

The update is the sensitive half. Zanskar's releases carry cosign signatures and SLSA
provenance and build reproducibly; an in-place updater that trusted anything the web
process downloaded would hand a stolen administrator session a way to install arbitrary
code as root. The updater must verify on its own.

## Decision

**Every host action is a request to systemd, authorised by polkit rules the package
ships, never a privilege the gateway holds.**

- **Restart gateway** stays what it is: drain live sessions, exit, systemd starts the
  process again (`POST /admin/system/restart`). It moves into the gear menu.
- **Reboot host** and **Stop host** ask `org.freedesktop.login1` over D-Bus for `Reboot`
  and `PowerOff`. A polkit rule installed by the deb allows exactly those two actions for
  the `zanskar` user. Both drain first. Stop carries a warning the dialog states plainly:
  nothing in the portal can start a stopped machine; recovery needs the host or the cloud
  console.
- **Update** writes the requested version to `/var/lib/zanskar/update-request` and asks
  `org.freedesktop.systemd1` to start `zanskar-update.service`, a root-owned oneshot unit
  the deb ships; the polkit rule allows the `zanskar` user to start that one unit and no
  other. The unit's script validates the version string (`v<major>.<minor>.<patch>`,
  newer than the running one — never a downgrade), downloads the release package, its
  checksums and signature from the GitHub release, runs `cosign verify-blob` pinned to the
  release workflow's certificate identity and OIDC issuer (keyless signing, as the install
  docs already verify by hand), checks the SLSA provenance the same way, and only then
  installs with `dpkg` and restarts the service. A failure leaves the running version in
  place and writes the reason to a status file the console shows. The web process never
  downloads a binary and never writes outside its own state directory.
- **Version check**: once a day the gateway fetches a small manifest from the project
  site (version and release-notes URL; no identifying data sent; honours proxy settings;
  runtime setting `updates.check`, default on). A newer version lights the bell.
- **Guards on every action**: admin role; an MFA step-up — a TOTP code entered within the
  last few minutes, so an account without an authenticator cannot perform host actions at
  all; a typed confirmation (the gateway's hostname); an audit event *before* the action
  (`system.reboot`, `system.poweroff`, `system.update` with the version) so a reboot that
  succeeds still leaves its trace.
- **Where it does not apply**: on Docker, Helm or an unknown supervisor the actions are
  hidden and the endpoints answer 409 `unsupported_supervisor`; the bell still reports a
  new version with the upgrade instructions for that deployment.

## Amendment (2026-10-15, at build time)

Two refinements from building it. The gateway does not ask systemd to start the update
unit at all: it writes the request file after the drain, and a **path unit**
(`zanskar-update.path`) the package ships starts `zanskar-update.service` when the file
appears. The gateway therefore needs no polkit grant for `manage-units` — a rule that, on
the older polkit still in Ubuntu 22.04, could not have been limited to one unit — and the
installer removes the file first, so a failure never loops. And `cosign` is a package
*recommendation* rather than a hard dependency, so the package still installs where it is
missing; the installer refuses to run without it and says so on the bell.

## Consequences

- A stolen administrator session with a current TOTP can reboot or stop the gateway and
  can install a *newer, signed* release — the blast radius is bounded by the signature
  check and the downgrade refusal; it is never "run anything as root".
- The deb gains two polkit rules, the update unit and its script, and the state file;
  `cosign` becomes a hard dependency of the package where it was a documented step.
- New audit actions and endpoints under `/api/v1/admin/system/`; the gear and bell live in
  the console's corner strip beside the command line, so the WAF path story of ADR 0029 is
  unchanged.
- Documentation: a page on host actions and what the update verifies.

## Alternatives considered

- **`sudo` from the handler** — blocked by `NoNewPrivileges`, and rightly; weakening the
  unit to allow it would widen the host exposure for every other bug.
- **A long-running root agent with its own socket** — more code to get right than two
  polkit rules and a oneshot unit, for the same capability.
- **The gateway downloads and verifies the release itself** — leaves the privileged step
  trusting the unprivileged one; rejected.
- **No stop action** — the user chose to keep it with the guards above.
