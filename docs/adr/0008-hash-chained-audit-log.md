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
