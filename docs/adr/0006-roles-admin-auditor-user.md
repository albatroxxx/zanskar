# 0006. Roles: admin, auditor, user

Date: 2026-09-20

## Status

Accepted

## Context

The original plan had two portals, admin and user, with session recordings visible only to admins.
That makes the people who grant access the same people who review how it was used. SOC 2, PCI DSS
and ISO 27001 auditors look for separation of duties between those two functions.

## Decision

Zanskar has three roles. A user may hold more than one.

- `user`: can see targets their policies grant, connect to them, and see the metadata of their
  own past sessions (start, end, target). Cannot view recordings, even their own.
- `admin`: can manage users, groups, identity providers, targets, credentials, policies, and
  autoscaling groups, terminate sessions, and read the audit log and session recordings.
- `auditor`: can read the audit log, verify the hash chain, and view every recording and every
  session's metadata. Cannot change any configuration. This is the role for security, compliance
  and external reviewers who must never be able to alter what they are reviewing.

Separation of duties comes from two properties rather than from hiding the log from admins:

1. **Nobody can alter the log.** Audit rows are insert-only at the database role level and hash
   chained (ADR 0008). Recordings are content-addressed by SHA-256. An admin can read what they
   did; they cannot rewrite it.
2. **Every read is itself recorded.** Each recording view and each audit log query produces an
   audit event naming the reader, regardless of role.

Role assignment is done by an admin. An admin cannot remove the last admin. Granting `admin` or
`auditor` is an audit event.

Amended 2026-09-20: the first draft withheld recordings and the audit log from `admin`. The
project owner decided admins keep read access alongside designated auditors.

## Consequences

- Small teams can run with admins only and still have a complete, tamper-evident record.
  Organisations that need an independent reviewer grant `auditor` to people who hold no `admin`.
- The UI is one application with three role-gated route trees rather than two portals (ADR 0010).
  The admin portal gains read-only Audit and Recordings sections; the auditor portal contains only
  those sections.
- The policy engine and every handler check roles server-side. The UI only hides what the API
  would refuse anyway.
- The compliance mapping in the threat model relies on log immutability and read auditing, not on
  admins being unable to read the log.
