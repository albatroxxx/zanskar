# 0019. Targets and autoscaling groups are retired, not erased

Date: 2026-09-28

## Status

Accepted

## Context

Deleting a target was a hard `DELETE` with `ON DELETE SET NULL` on `access_sessions.target_id`.
That row also carries `CHECK (target_id IS NOT NULL OR asg_instance_id IS NOT NULL)`, so the
first delete of any target that had ever been connected to failed inside the database and the
admin saw a red "internal error" banner (manual QA finding R19). Autoscaling groups had the
same shape through `asg_instance_id`. Had the delete gone through, every past session, recording
label and audit event for that machine would have lost its name and shown a bare id, which is
the opposite of what a reviewer needs.

Separately, nothing stopped an admin from deleting a target that a policy still named by id or
that had a session open. The confirm dialog promised "past sessions keep their records" and the
API description promised open sessions would be terminated; neither was true.

## Decision

1. **Retire, do not erase.** `targets` and `autoscaling_groups` gain `deleted_at`. Delete sets it
   (and `status = 'disabled'`), drops the row's credential bindings so the credentials themselves
   can later be deleted, and leaves everything else in place. Every repository lookup and listing
   filters `deleted_at IS NULL`; only the history queries in package `session` (session labels,
   audit name resolution) read past it. Instance rows of a retired group stay for the same reason.
2. **Names are unique among live rows only.** The inline `UNIQUE (name)` becomes a partial unique
   index `WHERE deleted_at IS NULL`, so a retired name can be enrolled again under a new id. On
   SQLite this needs a table rebuild (migration `0012_retire_targets`, foreign keys off during the
   rebuild as in 0006 and 0010); on Postgres it is a constraint swap.
3. **Refuse while in use.** Delete answers `409 in_use` when any policy's selector names the
   target or group by id (tag selectors are not references; they match whatever carries the
   tags), or when a session is open on the target or on any instance of the group. The message
   names the policies and counts the sessions so the admin knows what to change. The refusal is
   an audit event with outcome failure.

## Consequences

- Session history, recordings and the audit log keep resolving machine names forever, which the
  planned name-not-id clean-up of the admin tables (QA findings R15, R26, R28) relies on.
- Retired rows accumulate. They are small and carry no secrets (bindings are dropped); a purge of
  rows older than the recording retention window can follow if it ever matters.
- Pending access requests for a retired target are not touched. Approving one grants nothing:
  connect answers `404` because the target no longer resolves.
- The API no longer claims to terminate open sessions on delete. Terminating is an explicit
  admin action on the session; deletion waits for it.
