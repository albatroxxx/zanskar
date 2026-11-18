-- migrate: foreign_keys=off
-- Approvers (ADR 0049): a fourth role, approver, which the user_roles CHECK
-- must admit; and a request a person may withdraw, status cancelled, which
-- the access_requests CHECK must admit. Cloud accounts (ADR 0050): a role in
-- an AWS account is a target, derived from cloud_role_arn as a cluster is
-- from its API server; it serves one protocol, cloud, which the three
-- protocol CHECKs must admit. SQLite cannot alter a CHECK in place, so the
-- tables that carry one are rebuilt as 0056 rebuilt them, each carrying
-- every column it has; recordings and app_sessions reference
-- access_sessions, so foreign keys are off for the rebuild (the framework
-- checks for dangling references after). access_requests is rebuilt once
-- for both its CHECKs.
ALTER TABLE targets ADD COLUMN cloud_platform TEXT;
ALTER TABLE targets ADD COLUMN cloud_account_id TEXT;
ALTER TABLE targets ADD COLUMN cloud_account_alias TEXT;
ALTER TABLE targets ADD COLUMN cloud_role_arn TEXT;
ALTER TABLE targets ADD COLUMN cloud_external_id TEXT;
ALTER TABLE targets ADD COLUMN cloud_max_minutes INTEGER;
ALTER TABLE targets ADD COLUMN cloud_region TEXT;

CREATE TABLE user_roles_new (
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role     TEXT NOT NULL CHECK (role IN ('admin', 'auditor', 'approver', 'user')),
    PRIMARY KEY (user_id, role)
);
INSERT INTO user_roles_new (user_id, role) SELECT user_id, role FROM user_roles;
DROP TABLE user_roles;
ALTER TABLE user_roles_new RENAME TO user_roles;

CREATE TABLE target_credentials_new (
    target_id      TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    protocol       TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http', 'kube', 'pod', 'cloud')),
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
    protocol                  TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http', 'kube', 'pod', 'cloud')),
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
    protocol           TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http', 'kube', 'pod', 'cloud')),
    reason             TEXT NOT NULL,
    requested_minutes  INTEGER NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'revoked', 'cancelled')),
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
