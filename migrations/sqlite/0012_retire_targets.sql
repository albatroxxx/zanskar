-- migrate: foreign_keys=off
-- Targets and autoscaling groups are retired, not erased (ADR 0019): the row
-- stays, so past sessions, recordings and audit events keep resolving to the
-- machine's name, while every listing and lookup filters on deleted_at. The
-- inline UNIQUE on name gives way to a partial unique index so a retired name
-- can be enrolled again. SQLite cannot drop an inline constraint, so both
-- tables are rebuilt; access_sessions, access_requests, target_credentials,
-- asg_credentials and asg_instances reference them, so foreign keys are off
-- for the rebuild (the framework checks for dangling references afterwards).
CREATE TABLE targets_new (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    address               TEXT NOT NULL,
    os_family             TEXT NOT NULL CHECK (os_family IN ('linux', 'windows', 'other')),
    ports                 TEXT NOT NULL DEFAULT '{}',
    capabilities          TEXT NOT NULL DEFAULT '[]',
    host_key_fingerprint  TEXT,
    host_key_status       TEXT NOT NULL DEFAULT 'unknown' CHECK (host_key_status IN ('unknown', 'pending', 'trusted', 'changed')),
    tls_fingerprint       TEXT,
    tags                  TEXT NOT NULL DEFAULT '{}',
    status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    notes                 TEXT NOT NULL DEFAULT '',
    created_by            TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    last_probed_at        TEXT,
    winrm_tls_fingerprint TEXT,
    engine                TEXT,
    engine_version        TEXT,
    deleted_at            TEXT
);
INSERT INTO targets_new (id, name, address, os_family, ports, capabilities, host_key_fingerprint, host_key_status,
        tls_fingerprint, tags, status, notes, created_by, created_at, updated_at, last_probed_at,
        winrm_tls_fingerprint, engine, engine_version)
    SELECT id, name, address, os_family, ports, capabilities, host_key_fingerprint, host_key_status,
        tls_fingerprint, tags, status, notes, created_by, created_at, updated_at, last_probed_at,
        winrm_tls_fingerprint, engine, engine_version FROM targets;
DROP TABLE targets;
ALTER TABLE targets_new RENAME TO targets;
CREATE UNIQUE INDEX targets_name_live_idx ON targets(name) WHERE deleted_at IS NULL;

CREATE TABLE autoscaling_groups_new (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    provider               TEXT NOT NULL CHECK (provider IN ('aws')),
    region                 TEXT NOT NULL,
    external_name          TEXT NOT NULL,
    role_arn               TEXT NOT NULL,
    external_id            TEXT NOT NULL,
    os_family              TEXT NOT NULL CHECK (os_family IN ('linux', 'windows', 'other')),
    ports                  TEXT NOT NULL DEFAULT '{}',
    capabilities           TEXT NOT NULL DEFAULT '[]',
    address_preference     TEXT NOT NULL DEFAULT 'private' CHECK (address_preference IN ('private', 'public')),
    poll_interval_seconds  INTEGER NOT NULL DEFAULT 30,
    tags                   TEXT NOT NULL DEFAULT '{}',
    status                 TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    last_synced_at         TEXT,
    last_error             TEXT,
    created_by             TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL,
    deleted_at             TEXT
);
INSERT INTO autoscaling_groups_new (id, name, provider, region, external_name, role_arn, external_id, os_family, ports,
        capabilities, address_preference, poll_interval_seconds, tags, status, last_synced_at, last_error, created_by,
        created_at, updated_at)
    SELECT id, name, provider, region, external_name, role_arn, external_id, os_family, ports,
        capabilities, address_preference, poll_interval_seconds, tags, status, last_synced_at, last_error, created_by,
        created_at, updated_at FROM autoscaling_groups;
DROP TABLE autoscaling_groups;
ALTER TABLE autoscaling_groups_new RENAME TO autoscaling_groups;
CREATE UNIQUE INDEX autoscaling_groups_name_live_idx ON autoscaling_groups(name) WHERE deleted_at IS NULL;
