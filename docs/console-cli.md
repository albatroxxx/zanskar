# The console command line

<!-- Generated from internal/cli by hack/gen-cli-docs. Do not edit by hand. -->

Administrators can work from a command line inside the console: the terminal-window icon at the
top right of every administrator page, or Ctrl+`, opens it at the bottom of the page. It
runs Zanskar commands only. It is not a shell, and it cannot reach the gateway's host
([ADR 0027](adr/0027-restricted-console-cli.md)).

## How it works

- **A fresh code opens it.** The first time you open it, and again after 15 minutes without a
  command, it asks for a code from your authenticator app (a recovery code also works). You
  need an authenticator enrolled; an account that signs in only through an identity provider
  cannot open it. Five wrong codes close it for 15 minutes; your sign-in is not affected.
- **It does what the console does, no more.** Each command makes the same API request the
  console would, through the same permission checks. Anything the console would refuse you,
  the command line refuses too.
- **Changes ask first.** Commands that end, remove or restart something say what will happen
  and ask you to type a word, usually the name of what you are changing. Anything else
  cancels.
- **Every line is recorded.** Each line you run, including the ones that only read, is an
  audit event (`cli.command`) with its result and the routes it called. A change also
  has its usual event just before it.
- **Not a shell.** Pipes, redirection, variables and command substitution are refused, and so
  is anything not in the list below. Host operations (backup, restore, key rotation, audit
  repair) are not commands: they need the host on purpose.
- **No secrets.** No command takes a password, key or token; setting those stays in the
  console's forms.
- **Turning it off.** Set `ZANSKAR_CONSOLE_CLI=off` in the environment file and restart.
  It is not a console setting, so a stolen sign-in cannot turn it back on.

Names work wherever there is one (users, targets, policies, autoscaling groups); ids work too. Sessions and
access requests are named by the first 8 characters of their id, as the lists show them; 6 are
enough when they are unique. Words with spaces go in quotes: `setting set login_banner "Use is monitored"`.

The console also understands `clear` and `history`, and the up and down arrows recall earlier
lines.

## General

### `help [command]`

List the commands, or show how to use one.

```
zanskar> help user disable
```

### `status`

Gateway health, audit chain, live sessions and waiting requests.

```
zanskar> status
```

### `version`

The gateway's version.

```
zanskar> version
```

## Sessions

### `sessions [--live] [--user <username>] [--target <name>] [--last <n>]`

Sessions through the gateway, newest first.

- `--live`: only sessions still open
- `--user <username>`: one user's sessions
- `--target <name>`: sessions to one target
- `--last <n>`: how many, newest first (default 20)

```
zanskar> sessions --live
```

### `session show <id>`

One session in full. The id can be the first 8 characters shown by sessions.

```
zanskar> session show 3f9a1c20
```

### `session terminate <id>`

End a live session now. Its recording stops at that moment. Asks you to confirm first.

```
zanskar> session terminate 3f9a1c20
```

## Users

### `users [--role <role>]`

People who can sign in.

- `--role <role>`: admin, auditor or user

```
zanskar> users --role admin
```

### `user show <username>`

One user in full.

```
zanskar> user show alice
```

### `user disable <username>`

Stop a user signing in, and sign them out everywhere. Asks you to confirm first.

```
zanskar> user disable alice
```

### `user enable <username>`

Let a disabled user sign in again.

```
zanskar> user enable alice
```

### `user reset-mfa <username>`

Remove a user's authenticator; they enrol a new one at next sign-in. Asks you to confirm first.

```
zanskar> user reset-mfa alice
```

### `user signout <username>`

End all of a user's console sign-ins. Asks you to confirm first.

```
zanskar> user signout alice
```

## Targets

### `targets [--tag <key=value>] [--search <text>]`

Hosts and databases the gateway can reach.

- `--tag <key=value>`: only targets with this tag
- `--search <text>`: name or address contains

```
zanskar> targets --tag env=prod
```

### `target show <name>`

One target in full.

```
zanskar> target show web-01
```

### `target probe <name>`

Connect to a target to learn what it offers. Trust is not changed.

```
zanskar> target probe web-01
```

## Access

### `policies`

Access policies.

```
zanskar> policies
```

### `policy show <name>`

One policy in full.

```
zanskar> policy show prod-db-jit
```

### `requests [--pending]`

Access requests, newest first.

- `--pending`: only requests waiting for a decision

```
zanskar> requests --pending
```

### `request approve <id> [note]`

Approve a request; the note is shown to the requester.

```
zanskar> request approve 9c1d2e3f ok for the incident
```

### `request deny <id> [note]`

Deny a request; the note is shown to the requester.

```
zanskar> request deny 9c1d2e3f use the staging copy
```

### `request revoke <id>`

Withdraw an approved request before it expires. Asks you to confirm first.

```
zanskar> request revoke 9c1d2e3f
```

## Audit

### `events [--user <username>] [--action <action>] [--last <n>]`

The audit log, newest first.

- `--user <username>`: events by one person
- `--action <action>`: one kind of event, e.g. session.start
- `--last <n>`: how many, newest first (default 20)

```
zanskar> events --user alice --last 10
```

### `audit verify`

Walk the hash chain and check that no event was altered or removed.

```
zanskar> audit verify
```

## Gateway

### `logs [--last <n>] [--level <level>] [--search <text>]`

The gateway's recent log.

- `--last <n>`: how many lines (default 30)
- `--level <level>`: debug, info, warn or error and above
- `--search <text>`: lines containing this

```
zanskar> logs --level warn
```

### `tls`

How the gateway serves HTTPS and the certificate in use.

```
zanskar> tls
```

### `storage`

Where recordings are kept.

```
zanskar> storage
```

### `storage test`

Write and read back a test object in the recordings store.

```
zanskar> storage test
```

### `settings`

Runtime settings and where each value comes from.

```
zanskar> settings
```

### `setting get <key>`

One setting in full.

```
zanskar> setting get log.level
```

### `setting set <key> <value>`

Change a runtime setting. Secrets are never set here. Asks you to confirm first.

```
zanskar> setting set log.level debug
```

### `restart [--wait <minutes>]`

Restart the gateway once live sessions end, as the console does. Asks you to confirm first.

- `--wait <minutes>`: how long live sessions may finish first; 0 ends them now (default 15)

```
zanskar> restart --wait 5
```

### `restart cancel`

Cancel a restart that is waiting for sessions to end.

```
zanskar> restart cancel
```

## Autoscaling

### `asgs`

Autoscaling groups the gateway follows.

```
zanskar> asgs
```

### `asg sync <name>`

Read the group's instances from the cloud now.

```
zanskar> asg sync web-fleet
```
