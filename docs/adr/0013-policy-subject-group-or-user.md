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

Amended 2026-09-29: a policy's protocols applied to all of its targets, so "ssh to the fleet,
rdp to the two jump hosts" for one team took two policies with the same windows, limits and
flags to keep in step (manual QA finding R13). A policy now carries optional **rules**, each a
`target_selector` plus `protocols`, evaluated alongside the base pair; the base is the first
rule and may be empty when rules carry everything. A rule inherits the policy's windows, limits
and flags; there are no per-rule limits, by design: one policy is one set of conditions for one
subject, and rules only say which protocols on which machines. `Policy.Covers` is the single
decision every caller uses (the connect gate, the target list, the approval eligibility check),
and `Policy.References` is what the deletion guard scans, so a machine named only inside a rule
is still protected from deletion.

Amended 2026-10-11, revocation reaches live sessions: a change that took access away only
stopped new connects, and a session already open ran on until its idle or maximum time ran out
(security review finding H5). Each live session is now registered under the policy that
admitted it, and the changes that take access away end the sessions they take it from, at once:

- **Editing a policy** checks each live session it admitted against the saved policy alone. The
  session ends unless the policy still applies to the user (bound to them, or to a group they
  are in), is enabled, allows the session's protocol on the session's machine, and has a time
  window open now. A session that cannot be checked, say because its machine cannot be looked
  up, is kept, and the gateway logs it.
- **Deleting a policy** ends every live session it admitted.
- **Removing a member from a group** ends that member's live sessions admitted by the group's
  policies. Sessions admitted by a policy bound to the user directly are untouched.
- **Deleting a group** ends the live sessions admitted by any of its policies, before the
  policies are deleted with the group. The group's audit event lists the policies that went.
- **Disabling, locking or deleting an account, changing its roles, or signing it out
  everywhere** ends all of that user's live sessions.

A session ended by a policy or group change closes as `policy_revoked`; one ended by an account
change, as `admin_terminated`. The audit event for each change records how many live sessions
it ended (`live_sessions_ended`). One limitation is by design: a policy change is checked
against that policy alone. If another policy would still let the user in, the session ends
anyway, and the user reconnects through the other policy. Nothing re-checks a session on a
timer, so a time window that closes during a session does not end it (the policy's maximum
session length bounds it), and an approved request that expires still leaves its sessions
running (ADR 0018). Like an admin's terminate, revocation reaches the sessions of the gateway
process that made the change, which is all of them while Zanskar runs as one instance.

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
