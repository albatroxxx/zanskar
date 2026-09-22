# 0015. Recording retention is admin-editable runtime policy

Date: 2026-09-22

## Status

Accepted

## Context

Session recordings accumulate without bound. On the single-instance deployment that is
one growing directory on one disk, so a deployment needs a way to expire old recordings.
Two questions follow: what the rule is, and where it lives.

Configuration in Zanskar is otherwise the environment only, deliberately (ADR-adjacent, in
`internal/config`; ADR 0014). But retention is not deployment configuration like a database
DSN or the master key — it is an operational policy a compliance owner adjusts over time
("keep 90 days", then "keep 180"), and requiring a redeploy to change it, or hiding it in a
file only the operator can reach, would put it in the wrong hands. It should be editable by
an administrator in the console.

Deleting recordings also touches the audit trail: `recording.view`, `session.start` and
`session.end` events reference a recording by id, and the hash chain must stay verifiable.
A retention sweep that removed the recording row would orphan those references.

## Decision

Recording retention is a single, admin-editable policy stored in the database and applied
by a background sweeper.

- **Model: age with a size backstop.** `max_age_days` keeps recordings for that many days;
  `max_total_bytes` is a safety valve that deletes the oldest early if the total would
  otherwise exceed it. Zero disables that dimension; both zero means keep everything, which
  is the default, so nothing is deleted until an administrator opts in.
- **Runtime, not deployment config.** The policy lives in a `retention_policy` row, is read
  and written through the admin API (`GET`/`PUT /api/v1/admin/retention`), and is edited in
  the admin console. Deployment configuration stays environment-only; this is the first
  operational setting that is runtime-editable, and the distinction is deliberate.
- **Admin only, always audited.** Only an administrator may change it; an auditor can read
  but not shorten it, so evidence cannot be quietly aged out. Every change writes a
  `retention.policy.update` event.
- **Delete the blob, keep the row.** The sweeper deletes the recording's blob (a new
  `Delete` on the storage interface, for both local and S3) and sets `purged_at` on the
  row, leaving the metadata so audit references still resolve. Each deletion writes a
  `recording.purge` event. Playback of a purged recording returns 410 Gone.
- **Idempotent and resilient.** The sweep reads candidates, then deletes; a blob-delete
  failure leaves the row unpurged so the next sweep retries. Deleting an already-absent
  blob is success.

## Consequences

- An administrator can set and change retention without a redeploy, and the change is on
  the record.
- The audit chain stays verifiable across purges, at the cost of keeping a small metadata
  row per purged recording forever.
- The single disk is protected by the size backstop even if the age window alone would let
  it fill.
- A `retention_policy` table introduces runtime-editable settings. Future operational
  settings can follow the same shape; deployment configuration does not.
