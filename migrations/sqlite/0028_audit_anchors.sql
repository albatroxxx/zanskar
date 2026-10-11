-- Signed anchors for the audit chain (ADR 0008, amended 2026-10-11). Each row
-- records the chain head (event id and hash) at a moment, with an HMAC-SHA256
-- made with a key derived from the master key, so a database-only attacker can
-- delete an anchor but cannot write or alter one. No foreign key to
-- audit_events: an anchor must outlive the event it names, or it could not
-- report that event missing.
CREATE TABLE audit_anchors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    INTEGER NOT NULL,
    hash        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    mac         TEXT NOT NULL
);
