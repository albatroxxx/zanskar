# 0008. Hash-chained audit log

Date: 2026-09-20

## Status

Accepted

## Context

The audit log is the evidence that an access gateway produces. An attacker who gains database
access, or an admin covering their tracks, will try to delete or rewrite entries. Compliance
frameworks require that audit records be protected from modification and that gaps be detectable.

Alternatives considered:

- **Write-only to an external SIEM.** Good, but not every deployment has one, and it does not
  protect the copy inside Zanskar.
- **Database triggers that block updates.** Bypassed by anyone with superuser access.
- **Sign each event.** Detects modification of an event but not deletion of a whole event.

## Decision

Audit events are stored in an append-only `audit_events` table. Each event carries `prev_hash`,
the hash of the previous event, and `hash`, computed as:

```
hash = SHA-256( prev_hash || canonical_json(event_without_hash) )
```

Canonical JSON means keys sorted, no insignificant whitespace, UTF-8, and timestamps in RFC 3339
UTC. The first event chains from a fixed genesis value. Insertion is serialized so that the chain
is linear.

The application's database role has INSERT and SELECT on `audit_events` and nothing else.

Periodically, and on demand, the gateway writes an anchor: the latest event ID and hash, signed
with the gateway's audit key, to an external location (object storage, syslog, a webhook, or
stdout). Anchors let a verifier prove that the chain was not truncated after the anchor time.

`zanskar audit verify` walks the chain, recomputes every hash, and compares against stored
anchors. It reports the first divergent event and the last matching anchor.

Every action that changes configuration, every login, every connect and disconnect, every
recording view, and every audit log query produces an event.

## Consequences

- Any deletion, insertion, or edit of an event breaks the chain from that point forward and is
  found by verification.
- Serialized insertion is a small throughput ceiling. Audit volume for an access gateway is low
  enough that this does not matter.
- Anchors need an external location to be meaningful. Without one, an attacker with full database
  access can truncate the tail and re-anchor. The documentation says so.
- Events are never deleted by the application. Retention is handled by archiving verified
  segments, never by deleting rows in place.

## Amendment (2026-10-11): anchors, as built

The anchors above were not built with the chain. Until now `zanskar audit verify` walked the
chain from the first event and nothing else, so deleting the newest events left a log that
linked and verified (security review finding M5). The first bullet under Consequences was
true only for events with a successor. This is what is built now.

**The anchor.** An anchor is `{event_id, hash, created_at, mac}`: the newest event's id and
hash, the time it was written (RFC 3339 UTC, whole microseconds, since PostgreSQL keeps no
more), and

```
mac = hex( HMAC-SHA256( anchor_key,
        "zanskar-audit-anchor-v1\n" || event_id || "\n" || hash || "\n" || created_at ) )
```

`anchor_key` is derived from the master key with HKDF-SHA256, info `zanskar audit anchor v1`,
the way the CSRF and OIDC-state keys are (ADR 0007). Someone with only database access can
delete an anchor but cannot write one or alter one, which is what "signed with the gateway's
audit key" asked for.

**When anchors are written.** The gateway writes one when it starts and every hour after,
skipping a head that already has an anchor signed with the current key, and
`zanskar audit anchor` writes one on demand and prints it as one line,
`anchor <event_id> <hash> <created_at> <mac>`, for an operator to keep elsewhere. Anchors are
stored in `audit_anchors`, with no foreign key to `audit_events`: an anchor has to outlive the
event it names, or it could not report that event missing. Writing an anchor never records an
audit event, which would move the head the anchor names.

**The copy outside the database.** Each new anchor is logged once, at INFO, as `audit anchor`
with the four fields (and once more at each start). The service's journal, stdout and stderr,
is the "stdout" location above, and it is the copy outside the database for as long as the
journal is shipped off the host. Anchors are not sent through the SIEM sinks: a sink carries
chain events through a checkpointed exporter, an anchor would need a message shape of its own in
each and would confuse receivers that use the event id as the idempotency key, and the SIEM
already receives every event's id and hash in chain order.

**What verify checks.** `zanskar audit verify`, `GET /api/v1/audit/verify` and the console's
audit page now also check:

1. every stored anchor's MAC under the current key; an anchor that does not verify is
   reported as not written by this gateway, and nothing it claims is used;
2. that the event each genuine anchor names is still in the log with the hash it signed; a
   missing or changed event is reported, and anchors past the end of the log are reported
   together as the newest events having been deleted;
3. the id sequence's high-water mark against the newest event: `sqlite_sequence` on SQLite,
   the `last_value` of `audit_events_id_seq` on PostgreSQL (read with the newest id under the
   writers' advisory lock, so an insert in flight is not mistaken for a deletion);
4. on the command line, with `--anchor "<line>"` (repeatable), anchors kept outside the
   database, in the same way.

The result reports the last matching anchor, the problems and any warnings. `intact` is false
on a broken chain and on any problem, so a log whose newest events were deleted no longer
reads as intact. Verify needs the anchor key and refuses to run without it rather than skip
the signatures. The command exits 0 when the log is intact, 1 when it is not and 2 on a
malformed command line.

**The sequence check, and what it cannot do.** SQLite writes `sqlite_sequence` in the
inserting transaction, so a rolled-back insert does not advance it; a mark above the newest id
means rows were deleted from the end, or the sequence row was edited, and is reported as a
problem. A PostgreSQL sequence is not transactional: a failed or rolled-back insert uses up its
id, and recovery after a crash can skip up to 32 ahead. There the same finding is a warning,
"the newest events may have been deleted, or an insert failed", and does not make `intact`
false. Either way the check is a tripwire, not a proof: someone with full database access can
delete the newest events, delete the stored anchors and rewind the sequence, and the stored
checks then pass. Only an anchor kept outside the database, checked with `--anchor`, catches
that, which is the Consequence above in so many words.

**Rotation and reseal.** `zanskar key rotate-master` re-signs the stored anchors under the new
key; an anchor that does not verify under the old key is left as it is, so verify keeps
reporting it. An anchor line kept outside the database from before a rotation verifies only
under the old key, so after rotating, restart the service at once (until it restarts it still
signs with the old key), run `zanskar audit anchor` and keep the new line. `zanskar audit
reseal` removes, in its own transaction, the stored anchors over the events it rewrites, since
those hashes are gone; an anchor over an event that is missing stays, so the gap is still
reported. It records how many it removed in the `audit.reseal` event and anchors the new head.
Lines kept outside the database for rewritten events stop verifying, which is the record that
the log was rewritten.

**Still to do.** Writing anchors to object storage, or to a webhook of their own, so the copy
outside the database does not depend on the journal being shipped; and a verifier for an
exported log, which does not exist today.
