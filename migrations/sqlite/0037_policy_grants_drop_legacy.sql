-- migrate: foreign_keys=off
-- The legacy policy columns go, now that the data step (0036) has written
-- every policy's grants (ADR 0036). SQLite cannot drop columns with
-- constraints in place, so the table is rebuilt; the directive on the first
-- line keeps foreign keys off around it, or DROP TABLE would cascade into
-- the subjects and null the policy_id of every past session and request.
-- grants is NOT NULL: a row the data step has not converted stops this
-- migration rather than being dropped unconverted.
CREATE TABLE access_policies_new (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    description  TEXT NOT NULL DEFAULT '',
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    grants       TEXT NOT NULL DEFAULT '[]',
    created_by   TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
INSERT INTO access_policies_new (id, name, description, enabled, grants, created_by, created_at, updated_at)
SELECT id, name, description, enabled, grants, created_by, created_at, updated_at FROM access_policies;
DROP TABLE access_policies;
ALTER TABLE access_policies_new RENAME TO access_policies;
