# 0027. A restricted command line in the console

Date: 2026-10-05

## Status

Accepted.

## Context

Administrators asked for a command line in the console, like the CLI button in a FortiGate's
web interface: type `sessions` or `user disable bob` instead of clicking through pages.

The obvious build, a shell on the gateway host opened from the browser, is ruled out. The host
holds the master key, the sealed credentials, the SSH certificate authority's key and the audit
database. A host shell would turn one stolen administrator cookie into all of them, and it could
rewrite the audit log or run `zanskar audit reseal`, which 0008 (hash-chained audit log) and 0006
(roles) exist to prevent. Whoever has the host already has everything; the console must never be
a way to get the host.

The useful part of a CLI is speed and scripting-style precision over the things an administrator
already manages: users, sessions, targets, policies, requests, the audit log and the gateway's
status. All of that is already in the HTTP API, behind its roles, validation and audit events.

## Decision

The console gets a **command line that speaks only Zanskar commands**. It is a different way to
call the API the console already uses, never a shell.

**What it is**
- A terminal-window icon (a small window with `>_` inside) at the top right of every
  administrator page (also Ctrl+`) opens a terminal-styled panel
  that slides up from the bottom over the page and can be resized. It is built from ordinary
  page elements, a transcript and a prompt, rather than a terminal emulator, so screen readers,
  copying and code autofill work. Only administrators see the icon.
- The browser sends each command line to one endpoint, `POST /api/v1/admin/cli`, with the
  session cookie and CSRF token like any other console request. Nothing is long-lived: no
  WebSocket, no process, no PTY.
- The gateway parses the line against a fixed command table. A known command is turned into the
  same internal API request the console would make and dispatched through the same router, with
  the console request's own context (the signed-in user, client address and request id), so it
  passes the same `RequireRole` checks, input validation and audit events. **There is no second
  authorisation model**: the CLI can do exactly what the API lets this user do, and nothing more.
- The reply is plain text (tables and messages) for the terminal to print.

**What it is not**
- No system shell, no `exec`, no file access, no environment access. The parser has no pipes,
  redirection, globbing, variables or command substitution; a line is a command name and
  arguments, split on spaces with simple quotes. Anything else is "unknown command".
- **No host-level operations**, ever: `backup`, `restore`, `migrate`, `init`, `keygen`,
  `key rotate`, `key rotate-master`, `audit reseal` and `admin create` stay on the host CLI. They
  touch the master key, the database file or the audit chain's evidence, and must need the host.
- **No secrets on the command line.** Commands never take a password, key or token as an argument,
  because command lines are audited and kept in browser history. Anything that needs a secret
  (creating a password credential, setting a user's password) stays in the console forms.

**Every command is audited**
- Each line produces a `cli.command` audit event: who, the command name, its arguments, and the
  result (`ok`, `denied`, `invalid`, `error`). Read-only commands are audited too, so the log shows
  what an administrator looked at from the CLI, not only what they changed.
- When the command changes something, the API's own event (for example `session.terminate`) is
  recorded as well, just before the `cli.command` event, whose details list the routes the
  command called with their status codes, so the two can be read together.
- Output is never written to the audit log; the API never returns secrets anyway.

**Guard rails**
- **Fresh MFA to open it.** The CLI asks for a code from the administrator's authenticator unless
  the session proved one in the last 15 minutes, and again after 15 minutes without a command. A
  stolen cookie alone cannot use it. Only a proved code counts: the code at sign-in, confirming a
  new authenticator, or the CLI's own unlock (a recovery code works and is used up). Signing in
  through an identity provider, or with no authenticator where none is required, proves nothing,
  so an administrator without an authenticator cannot open the CLI. Sessions gain a "MFA proved
  at" time for this. Five wrong codes close the CLI for 15 minutes; the sign-in is unaffected.
- **Confirmation for destructive commands** (terminate a session, disable a user, reset MFA,
  revoke access, restart the gateway, change a setting): the gateway answers with what will
  happen and a one-time confirmation bound to that exact command, and the administrator types
  the object's name to proceed.
- Lines are limited to 1 KB and rate-limited per session. The parser has a fuzz target in CI.
- **On by default for administrators**, because it adds no capability the API does not already
  give them. `ZANSKAR_CONSOLE_CLI=off` in the environment turns it off; it is deliberately not a
  console setting, so a stolen administrator session cannot switch it back on.

**Commands in the first version**

| Area | Commands |
|---|---|
| General | `help [command]`, `status`, `version`, `clear`, `history` (the last two run in the browser) |
| Sessions | `sessions [--user U] [--target T]`, `session show <id>`, `session terminate <id>` |
| Users | `users [--role R]`, `user show <name>`, `user disable <name>`, `user enable <name>`, `user reset-mfa <name>`, `user signout <name>` |
| Targets | `targets [--tag k=v] [--search T]`, `target show <name>`, `target probe <name>` |
| Access | `policies`, `policy show <name>`, `requests [--pending]`, `request approve <id> [note]`, `request deny <id> [note]`, `request revoke <id>` |
| Audit | `events [--user U] [--action A] [--last N]`, `audit verify` |
| Gateway | `logs [--last N] [--level L] [--search T]`, `tls`, `storage`, `storage test`, `settings`, `setting get <key>`, `setting set <key> <value>`, `restart [--wait M]` (15 minutes for live sessions by default, as in the console), `restart cancel` |
| Autoscaling | `asgs`, `asg sync <name>` |

Objects are named by their name where they have one (users, targets, policies, groups), with ids
accepted too. New commands are added by adding a row to the command table and a test; each must
map to an existing API route.

A reference page in the docs lists every command with its arguments, an example and the role it
needs, generated from the command table so it cannot drift.

## Consequences

- Administrators get a fast, precise way to do routine work, and the audit log records CLI use
  line by line.
- The attack surface grows by one parser and one endpoint, both small and fuzzed. Because every
  command goes through the existing router, a bug in the CLI cannot grant a permission the API
  does not.
- Host-level operations stay on the host. The console still cannot reach the master key, the
  database file or the audit chain's repair tool.
- Sessions gain a "last MFA at" time, which later features (step-up for sensitive console pages)
  can reuse.
- Each new command needs an API route first; the CLI never grows features of its own.
- Not chosen: a recorded SSH session to the gateway host enrolled as a target. It would give a
  real shell, which is exactly what this decision keeps out of the browser. Operators who need
  the host use their normal host access.
- Later, if wanted: auditors could get a read-only subset (`events`, `audit verify`, `sessions`),
  which the router's role checks already allow.
