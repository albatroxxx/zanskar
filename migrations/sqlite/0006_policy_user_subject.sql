-- migrate: foreign_keys=off
-- A policy may bind to one user instead of a group (ADR 0013). SQLite cannot
-- drop NOT NULL in place, so the table is rebuilt. The directive on the first
-- line makes the migrator switch foreign keys off around this file: with them
-- on, DROP TABLE would cascade and null the policy_id of every past session.
CREATE TABLE access_policies_new (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL UNIQUE,
    description           TEXT NOT NULL DEFAULT '',
    enabled               BOOLEAN NOT NULL DEFAULT TRUE,
    group_id              TEXT REFERENCES groups(id) ON DELETE CASCADE,
    user_id               TEXT REFERENCES users(id) ON DELETE CASCADE,
    target_selector       TEXT NOT NULL,
    protocols             TEXT NOT NULL,
    time_windows          TEXT NOT NULL DEFAULT '[]',
    max_session_minutes   INTEGER,
    idle_timeout_minutes  INTEGER NOT NULL DEFAULT 15,
    allow_clipboard       BOOLEAN NOT NULL DEFAULT FALSE,
    allow_file_transfer   BOOLEAN NOT NULL DEFAULT FALSE,
    require_mfa           BOOLEAN NOT NULL DEFAULT TRUE,
    created_by            TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    CHECK ((group_id IS NULL) <> (user_id IS NULL))
);
INSERT INTO access_policies_new (id, name, description, enabled, group_id, target_selector, protocols, time_windows,
    max_session_minutes, idle_timeout_minutes, allow_clipboard, allow_file_transfer, require_mfa, created_by, created_at, updated_at)
SELECT id, name, description, enabled, group_id, target_selector, protocols, time_windows,
    max_session_minutes, idle_timeout_minutes, allow_clipboard, allow_file_transfer, require_mfa, created_by, created_at, updated_at
FROM access_policies;
DROP TABLE access_policies;
ALTER TABLE access_policies_new RENAME TO access_policies;
CREATE INDEX access_policies_group_idx ON access_policies(group_id);
CREATE INDEX access_policies_user_idx ON access_policies(user_id);
