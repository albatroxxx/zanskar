# 0014. Guided install writes the environment file

Date: 2026-09-22

## Status

Accepted

## Context

Zanskar is configured entirely from the environment; ADR-adjacent, `internal/config`
states plainly that there is deliberately no config file, because secrets belong in the
environment or a secret manager and everything else is small enough to be explicit.

That is the right runtime contract, but it makes first install harder than it should be.
An operator must know the two dozen `ZANSKAR_*` variables, which combinations are valid
(the binary refuses plain HTTP off loopback, TLS cert and key must be set together), how
to generate a master key, and that losing that key destroys every stored credential. The
1.0 release targets a single-instance deployment installed by hand or by a configuration
tool, so this first-run experience matters.

Two shapes could solve it: introduce a config file format the server reads, or add a
guided step that produces the environment the server already reads. A config file would
add a second, competing source of truth and reopen the secrets-in-a-file question the
no-config-file decision closed.

## Decision

Add `zanskar init`: a guided step that gathers the necessary inputs and writes an
environment file (default `/etc/zanskar/env`, mode 0600) that the process, under systemd
or otherwise, loads. It does not introduce a file the server parses; the server's only
configuration source remains the environment.

- It runs interactively with prompts and defaults, and non-interactively from flags or an
  answer file, so configuration tools and cloud-init can drive it.
- It only ever writes valid combinations: an operator chooses "own certificate" or "behind
  a TLS proxy on loopback", and `init` sets the matching variables so the server will not
  refuse to start.
- It generates the master key, and it **never regenerates a master key that an existing
  env file already contains** — a re-run reuses it, because a new key would orphan every
  encrypted secret.
- It checks prerequisites it can (writable data directory, guacd reachability when desktop
  access is enabled, certificate files parse) and reports what it cannot rather than
  writing a file that fails at first start.

`init` writes configuration only. Applying migrations and creating the first admin remain
the existing `migrate` and `admin create` commands; `init` prints them as the next steps.

## Consequences

- The runtime contract is unchanged: one source of truth, the environment. `init` is a
  convenience that produces it, not a parallel config system.
- The env file is the sole home of the master key on the box, so its 0600 mode and backup
  are called out by `init` and in the deploy docs.
- Re-running `init` on a configured host is safe for the master key but will otherwise
  overwrite settings; it refuses to overwrite an existing file without `--force`.
- If a future release adds new settings, `init` gains prompts for them; the server keeps
  reading plain environment variables regardless of how they were produced.
