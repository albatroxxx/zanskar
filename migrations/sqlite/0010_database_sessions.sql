-- migrate: foreign_keys=off
-- Allow the 'database' protocol for access sessions (ADR 0017). SQLite cannot
-- alter a CHECK in place, so access_sessions is rebuilt. recordings references
-- it, so foreign keys are off for the rebuild (the framework checks for dangling
-- references afterwards).
CREATE TABLE access_sessions_new (
    id                        TEXT PRIMARY KEY,
    user_id                   TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    policy_id                 TEXT REFERENCES access_policies(id) ON DELETE SET NULL,
    target_id                 TEXT REFERENCES targets(id) ON DELETE SET NULL,
    asg_id                    TEXT REFERENCES autoscaling_groups(id) ON DELETE SET NULL,
    asg_instance_id           TEXT REFERENCES asg_instances(id) ON DELETE SET NULL,
    protocol                  TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database')),
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
