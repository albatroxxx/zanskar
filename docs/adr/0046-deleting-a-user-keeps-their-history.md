# 0046. Deleting a user keeps their history

Date: 2026-11-04

## Status

Accepted 2026-11-04. The owner asked for it after the console refused to delete an account that
had connected once: "we should be able to delete users preserving every audit trail, without
compromising anything." Redaction of a deleted person's name is not part of it.

## Context

`access_sessions.user_id` and `recording_views.user_id` referenced `users(id)` with
`ON DELETE RESTRICT` (migrations 0001, 0010, 0031). A session or a recording view therefore kept
its account alive: the console and `DELETE /users/{id}` answered `409 has_history` and told the
admin to disable the account instead (ADR 0019's reasoning for targets, applied to people).

That made the user table do the job of the record. Nearly every real account has opened a
session, so in practice nobody could ever be deleted; the accounts of people who had left stayed
in the list, in the policies' audience pickers and in the identity provider's sync. The record
itself never needed the row: `audit_events` has always held the actor as plain text, with no
foreign key, "because audit rows must outlive users". Cloud audit logs work the same way. A
CloudTrail event keeps the principal's name and ARN as text, so deleting an IAM user changes
nothing about what was recorded.

## Decision

1. **A session and a recording view carry who the person was.** Both tables gain
   `user_username` and `user_display_name`, copied from the account when the row is written
   (`session.Repo.Start`, `RecordView`), beside `user_id`, which stays as plain text. The foreign
   key goes. Because nothing in the schema refuses an unknown id any more, those two writes look
   the account up first and return `ErrUnknownUser`.
2. **Migration 0054 backfills** the copies from `users` and drops the constraint: a constraint
   swap on PostgreSQL, a rebuild of both tables on SQLite (foreign keys off for it, as in 0010
   and 0031). Both sets keep the same file name.
3. **Readers show the account while it exists and the copy once it does not.** Session lists and
   details, the audit label of a session or recording, command and output search, and the
   session filter by username use `COALESCE(u.username, s.user_username)`. A session of a deleted
   account carries `user_deleted: true`, and the console writes `alice (deleted)`.
4. **The audit log names a deleted actor too.** Resolving a user id that no longer exists reads
   the username the `user.delete` event recorded, and for an account deleted before that event
   did, the copy on its sessions; the name is marked `(deleted)`. The audit filter by actor name
   finds a deleted person the same way.
5. **Delete refuses only what is unsafe:** your own account and the last active admin. Its
   sign-ins are revoked and its live sessions end first, as before. `HasHistory`, `ErrHasHistory`
   and the `has_history` answer are removed.
6. **A new account with the same username is a different person.** The history is keyed by the
   id. It stays with the old id, and the new account starts with none.

## Consequences

- Deleting is possible for every account. Disabling stays, for access that may come back.
- The username and display name of a deleted person remain in sessions, recording views and the
  audit log. That is the record, not a leak: it is what "who connected on Oct 31" needs. A way to
  blank those fields for a data-erasure request was left out on purpose; it can be added as its
  own action that keeps ids and events and clears names.
- Rows with no copy (sessions the migration found no account for) show a short id, as a
  session whose account was missing already did.
- Command and output search hits and recording-view rows read the name but carry no deleted
  marker; the session they belong to does.
- Retiring targets and groups (ADR 0019) is unchanged: a machine's name is not personal data and
  those rows stay.
