-- migrate: foreign_keys=off
-- A Kubernetes cluster is a target (ADR 0045, built under ADR 0048): its API
-- server's URL makes it one, as an engine makes a database and an upstream
-- an application. It serves two protocols, kube (the API, through the
-- gateway as the person) and pod (a shell into a container), which the
-- protocol CHECKs must admit. SQLite cannot alter a CHECK in place, so the
-- three tables that carry one are rebuilt, as 0031 and 0054 rebuilt them;
-- recordings and app_sessions reference access_sessions, so foreign keys
-- are off for the rebuild (the framework checks for dangling references
-- after). target_credentials never had http in its CHECK here (0031 widened
-- it on Postgres only; an application binds nothing, so it never mattered);
-- it carries the whole list from now on. A cluster binds a credential of two
-- new types, kube_token and kube_client_cert, which the credentials table's
-- own CHECK must admit; that table was never rebuilt since 0001, so its
-- rebuild carries every column added since (0022, 0023).
ALTER TABLE targets ADD COLUMN kube_api_server TEXT;
ALTER TABLE targets ADD COLUMN kube_ca TEXT;
ALTER TABLE targets ADD COLUMN kube_impersonate INTEGER;

CREATE TABLE credentials_new (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL UNIQUE,
    type                    TEXT NOT NULL CHECK (type IN ('password', 'ssh_key', 'ssh_ca', 'domain', 'ec2_instance_connect', 'kube_token', 'kube_client_cert')),
    mode                    TEXT NOT NULL CHECK (mode IN ('vaulted', 'user_supplied', 'passthrough')),
    username                TEXT,
    domain                  TEXT,
    secret_enc              BLOB,
    public_key              TEXT,
    key_version             INTEGER REFERENCES key_versions(id),
    created_by              TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    rotated_at              TEXT,
    certificate_ttl_seconds INTEGER,
    certificate_principals  TEXT NOT NULL DEFAULT '[]',
    pending_secret_enc      BLOB,
    pending_public_key      TEXT,
    pending_key_version     INTEGER REFERENCES key_versions(id),
    pending_created_at      TEXT,
    retired_public_key      TEXT,
    retired_at              TEXT
);
INSERT INTO credentials_new (id, name, type, mode, username, domain, secret_enc, public_key, key_version, created_by, created_at, updated_at, rotated_at,
        certificate_ttl_seconds, certificate_principals, pending_secret_enc, pending_public_key, pending_key_version, pending_created_at, retired_public_key, retired_at)
    SELECT id, name, type, mode, username, domain, secret_enc, public_key, key_version, created_by, created_at, updated_at, rotated_at,
        certificate_ttl_seconds, certificate_principals, pending_secret_enc, pending_public_key, pending_key_version, pending_created_at, retired_public_key, retired_at
    FROM credentials;
DROP TABLE credentials;
ALTER TABLE credentials_new RENAME TO credentials;

CREATE TABLE target_credentials_new (
    target_id      TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    protocol       TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http', 'kube', 'pod')),
    credential_id  TEXT NOT NULL REFERENCES credentials(id) ON DELETE RESTRICT,
    PRIMARY KEY (target_id, protocol)
);
INSERT INTO target_credentials_new (target_id, protocol, credential_id)
    SELECT target_id, protocol, credential_id FROM target_credentials;
DROP TABLE target_credentials;
ALTER TABLE target_credentials_new RENAME TO target_credentials;

CREATE TABLE access_sessions_new (
    id                        TEXT PRIMARY KEY,
    user_id                   TEXT NOT NULL,
    user_username             TEXT NOT NULL DEFAULT '',
    user_display_name         TEXT NOT NULL DEFAULT '',
    policy_id                 TEXT REFERENCES access_policies(id) ON DELETE SET NULL,
    target_id                 TEXT REFERENCES targets(id) ON DELETE SET NULL,
    asg_id                    TEXT REFERENCES autoscaling_groups(id) ON DELETE SET NULL,
    asg_instance_id           TEXT REFERENCES asg_instances(id) ON DELETE SET NULL,
    protocol                  TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http', 'kube', 'pod')),
    credential_id             TEXT REFERENCES credentials(id) ON DELETE SET NULL,
    client_ip                 TEXT NOT NULL,
    user_agent                TEXT NOT NULL DEFAULT '',
    started_at                TEXT NOT NULL,
    ended_at                  TEXT,
    end_reason                TEXT,
    failover_from_session_id  TEXT REFERENCES access_sessions(id) ON DELETE SET NULL,
    end_detail                TEXT,
    CHECK (target_id IS NOT NULL OR asg_instance_id IS NOT NULL)
);
INSERT INTO access_sessions_new (id, user_id, user_username, user_display_name, policy_id, target_id, asg_id, asg_instance_id,
        protocol, credential_id, client_ip, user_agent, started_at, ended_at, end_reason, failover_from_session_id, end_detail)
    SELECT id, user_id, user_username, user_display_name, policy_id, target_id, asg_id, asg_instance_id,
        protocol, credential_id, client_ip, user_agent, started_at, ended_at, end_reason, failover_from_session_id, end_detail
    FROM access_sessions;
DROP TABLE access_sessions;
ALTER TABLE access_sessions_new RENAME TO access_sessions;
CREATE INDEX access_sessions_user_idx ON access_sessions(user_id, started_at);
CREATE INDEX access_sessions_open_idx ON access_sessions(ended_at) WHERE ended_at IS NULL;
CREATE INDEX access_sessions_started_idx ON access_sessions(started_at);

CREATE TABLE access_requests_new (
    id                 TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    policy_id          TEXT REFERENCES access_policies(id) ON DELETE SET NULL,
    target_id          TEXT REFERENCES targets(id) ON DELETE CASCADE,
    asg_id             TEXT REFERENCES autoscaling_groups(id) ON DELETE CASCADE,
    protocol           TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http', 'kube', 'pod')),
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
    grant_id           TEXT,
    CHECK (target_id IS NOT NULL OR asg_id IS NOT NULL)
);
INSERT INTO access_requests_new (id, user_id, policy_id, target_id, asg_id, protocol, reason, requested_minutes, status,
        approver_user_id, decision_note, decided_at, expires_at, created_at, updated_at, approved_minutes, extends_request_id, grant_id)
    SELECT id, user_id, policy_id, target_id, asg_id, protocol, reason, requested_minutes, status,
        approver_user_id, decision_note, decided_at, expires_at, created_at, updated_at, approved_minutes, extends_request_id, grant_id
    FROM access_requests;
DROP TABLE access_requests;
ALTER TABLE access_requests_new RENAME TO access_requests;
CREATE INDEX access_requests_user_idx ON access_requests (user_id);
CREATE INDEX access_requests_status_idx ON access_requests (status);
