# 0043. The configuration as a file: exported by name, imported through the API

Date: 2026-11-03

## Status

Accepted 2026-11-03, idea 10 of the 2026-11-03 live audit, which the owner asked to build. A
Terraform provider is a separate project and not part of this.

## Context

Hosts, applications, databases, groups and policies lived only in the gateway's database. Nobody
could review a change to them in a pull request, keep them in git, or rebuild a gateway from them
after a loss without restoring the whole database.

## Decision

1. **One YAML file, by name.** `zanskar: 1` (the format), then groups (with members by username),
   targets (hosts, databases, applications, with their credentials *named*), and policies
   (subjects by group name or username, grant targets by name). Ids never appear, so a file
   exported from one gateway imports into another. Autoscaling groups and identity providers are
   not in it: they hold cloud roles and secrets of their own.
2. **No secrets.** A credential is named, never copied; the gateway it is imported into must already
   hold one by that name. People are not created: a username must exist (an identity provider owns
   the person, ADR 0035).
3. **Through the API, in process.** Export reads, and import writes, by calling the gateway's own
   routes with the importing administrator's sign-in: the same validation, address rules (a target
   at a forbidden address is refused as it would be by hand), step-up, audit events and live-session
   re-checks. The package knows the API's JSON, not its repositories.
4. **Plan, then apply.** An import answers first with what it would change, each group, target and
   policy marked create, update or unchanged, and any problem (a name that does not exist). Any
   problem refuses the whole apply before it changes anything. Applied, it goes groups, targets,
   then policies, and stops at the first change the API refuses, saying which ran; there is no
   transaction across API calls. A policy's grants keep their ids where the kind matches by
   position, so access requests that point at them stay valid.
5. **Audited as a whole too.** `config.export` with the counts, `config.import` with what changed,
   beside each change's own event.

## Consequences

- A file can be reviewed and kept in git; re-importing an unchanged file changes nothing.
- An import is additive: what the file leaves out is not deleted. Deleting stays a deliberate act
  in the console.
- A hand-written file that omits defaults the export writes shows those objects as updates; the
  update is idempotent.
