# 0013. Access policies bind to a group or to a single user

Status: Accepted (2026-09-21)

## Context

Until now an access policy could only name a group. Every grant therefore went to every
member, and a one-off need (one operator who must reach one box for a week) forced a choice
between widening the whole group and creating a single-member group that then clutters the
group list and the membership audit trail. Operators asked for policies that name a person.

Alternatives considered:

- **Single-member "personal" groups created implicitly.** Keeps the schema, but leaks
  synthetic groups into every group listing, membership change and audit event, and a user
  with a personal group is no longer "in no group", which the UI and the SIEM export both
  treat as meaningful.
- **Per-user allow lists on the target.** Inverts the model: access would then be decided in
  two places, and the policy engine's session limits and time windows would not apply.

## Decision

A policy applies to exactly one subject: a group (`group_id`) or a user (`user_id`). The
database enforces that exactly one is set. A user's effective access is the union of the
policies bound to them directly and the policies bound to any group they belong to; the
engine evaluates that combined list exactly as before, protocol by protocol.

Nothing else about a policy changes: selectors, protocols, time windows and session limits
are the same for both subjects, and a policy can be moved between a group and a user by
editing it.

## Consequences

- One-off grants no longer widen a group. A user with no group memberships can still be
  given access.
- Overlap becomes more likely, since a user policy often sits beside a group policy for the
  same target. The existing tie-break stands: among matching policies the shortest idle
  timeout wins and its clipboard, file-transfer and MFA flags apply. Admins should keep the
  user policy at least as strict as the group policy in those flags, and a later change may
  take the most restrictive value of each flag instead.
- Access is additive only. A user policy cannot subtract what a group policy grants; to
  narrow one member's access, remove them from the group.
- SQLite cannot relax a NOT NULL column in place, so the migration rebuilds
  `access_policies`. The migrator gained a first-line directive
  (`-- migrate: foreign_keys=off`) that turns foreign keys off around such a file and checks
  the schema afterwards; without it the rebuild would null the policy link on every past
  session. PostgreSQL alters the columns in place.
- The API and UI expose the subject as "Applies to": a group or one user. Audit events for
  policies record whichever subject is set.
