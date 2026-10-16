-- migrate: foreign_keys=off
-- Applications (ADR 0033): an application is a target with an upstream the
-- gateway's proxy forwards to and a label it is served at under the apps
-- domain. Policies grant it under the protocol 'http', so the protocol CHECKs
-- of access_sessions and access_requests widen; SQLite cannot alter a CHECK in
-- place, so both tables are rebuilt, as 0010 rebuilt the first. The gateway
-- holds a second TLS certificate for the apps domain (kind 'apps'), so that
-- table is rebuilt too. app_sessions ties a browser's per-application cookie to
-- the access session it opened and the sign-in it came from. Foreign keys are
-- off for the rebuilds; the framework checks for dangling references after.
ALTER TABLE targets ADD COLUMN app_upstream TEXT;
ALTER TABLE targets ADD COLUMN app_label TEXT;
CREATE UNIQUE INDEX targets_app_label_live_idx ON targets(app_label) WHERE deleted_at IS NULL AND app_label IS NOT NULL;

CREATE TABLE access_sessions_new (
    id                        TEXT PRIMARY KEY,
    user_id                   TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    policy_id                 TEXT REFERENCES access_policies(id) ON DELETE SET NULL,
    target_id                 TEXT REFERENCES targets(id) ON DELETE SET NULL,
    asg_id                    TEXT REFERENCES autoscaling_groups(id) ON DELETE SET NULL,
    asg_instance_id           TEXT REFERENCES asg_instances(id) ON DELETE SET NULL,
    protocol                  TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http')),
    credential_id             TEXT REFERENCES credentials(id) ON DELETE SET NULL,
    client_ip                 TEXT NOT NULL,
    user_agent                TEXT NOT NULL DEFAULT '',
    started_at                TEXT NOT NULL,
    ended_at                  TEXT,
    end_reason                TEXT,
    failover_from_session_id  TEXT REFERENCES access_sessions(id) ON DELETE SET NULL,
    CHECK (target_id IS NOT NULL OR asg_instance_id IS NOT NULL)
);
INSERT INTO access_sessions_new SELECT * FROM access_sessions;
DROP TABLE access_sessions;
ALTER TABLE access_sessions_new RENAME TO access_sessions;
CREATE INDEX access_sessions_user_idx ON access_sessions(user_id, started_at);
CREATE INDEX access_sessions_open_idx ON access_sessions(ended_at) WHERE ended_at IS NULL;

CREATE TABLE access_requests_new (
    id                 TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    policy_id          TEXT REFERENCES access_policies(id) ON DELETE SET NULL,
    target_id          TEXT REFERENCES targets(id) ON DELETE CASCADE,
    asg_id             TEXT REFERENCES autoscaling_groups(id) ON DELETE CASCADE,
    protocol           TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http')),
    reason             TEXT NOT NULL,
    requested_minutes  INTEGER NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'revoked')),
    approver_user_id   TEXT REFERENCES users(id) ON DELETE SET NULL,
    decision_note      TEXT NOT NULL DEFAULT '',
    decided_at         TEXT,
    expires_at         TEXT,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    approved_minutes   INTEGER,
    extends_request_id TEXT REFERENCES access_requests(id) ON DELETE SET NULL,
    CHECK (target_id IS NOT NULL OR asg_id IS NOT NULL)
);
INSERT INTO access_requests_new SELECT * FROM access_requests;
DROP TABLE access_requests;
ALTER TABLE access_requests_new RENAME TO access_requests;
CREATE INDEX access_requests_user_idx ON access_requests (user_id);
CREATE INDEX access_requests_status_idx ON access_requests (status);

CREATE TABLE tls_certificates_new (
    kind         TEXT PRIMARY KEY CHECK (kind IN ('uploaded', 'generated', 'apps')),
    cert_pem     TEXT NOT NULL,
    key_enc      BLOB NOT NULL,
    key_version  INTEGER NOT NULL REFERENCES key_versions(id),
    created_by   TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at   TEXT NOT NULL
);
INSERT INTO tls_certificates_new SELECT * FROM tls_certificates;
DROP TABLE tls_certificates;
ALTER TABLE tls_certificates_new RENAME TO tls_certificates;

-- The cookie itself is never stored, only its SHA-256, as for sign-ins.
-- idle_seconds and expires_at carry the admitting policy's limits; the proxy
-- applies them on every request and a sweeper ends what went quiet.
CREATE TABLE app_sessions (
    token_hash       TEXT PRIMARY KEY,
    session_id       TEXT NOT NULL REFERENCES access_sessions(id) ON DELETE CASCADE,
    auth_session_id  TEXT NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    idle_seconds     INTEGER NOT NULL,
    expires_at       TEXT,
    created_at       TEXT NOT NULL,
    last_seen_at     TEXT NOT NULL
);
CREATE INDEX app_sessions_session_idx ON app_sessions(session_id);
