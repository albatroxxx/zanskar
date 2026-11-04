-- migrate: foreign_keys=off
-- An account can be deleted whatever it did (ADR 0046, which replaces the
-- reasoning of ADR 0019 for people). A session and a recording view named the
-- user with ON DELETE RESTRICT, so an account that had ever connected could
-- only be disabled. They now keep who it was the way audit_events does: the
-- id as plain text, with no foreign key, and the username and display name as
-- they were, copied in when the row is written. Readers show the live name
-- while the account exists and the copy once it is gone. SQLite cannot drop a
-- foreign key in place, so both tables are rebuilt, as 0031 rebuilt the first;
-- recordings and app_sessions reference access_sessions, so foreign keys are
-- off for the rebuild (the framework checks for dangling references after).
CREATE TABLE access_sessions_new (
    id                        TEXT PRIMARY KEY,
    user_id                   TEXT NOT NULL,       -- no FK: history must outlive the account
    user_username             TEXT NOT NULL DEFAULT '',
    user_display_name         TEXT NOT NULL DEFAULT '',
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
    end_detail                TEXT,
    CHECK (target_id IS NOT NULL OR asg_instance_id IS NOT NULL)
);
INSERT INTO access_sessions_new (id, user_id, user_username, user_display_name, policy_id, target_id, asg_id, asg_instance_id,
        protocol, credential_id, client_ip, user_agent, started_at, ended_at, end_reason, failover_from_session_id, end_detail)
    SELECT s.id, s.user_id, COALESCE(u.username, ''), COALESCE(u.display_name, ''), s.policy_id, s.target_id, s.asg_id, s.asg_instance_id,
        s.protocol, s.credential_id, s.client_ip, s.user_agent, s.started_at, s.ended_at, s.end_reason, s.failover_from_session_id, s.end_detail
    FROM access_sessions s LEFT JOIN users u ON u.id = s.user_id;
DROP TABLE access_sessions;
ALTER TABLE access_sessions_new RENAME TO access_sessions;
CREATE INDEX access_sessions_user_idx ON access_sessions(user_id, started_at);
CREATE INDEX access_sessions_open_idx ON access_sessions(ended_at) WHERE ended_at IS NULL;
CREATE INDEX access_sessions_started_idx ON access_sessions(started_at);

CREATE TABLE recording_views_new (
    id                TEXT PRIMARY KEY,
    recording_id      TEXT NOT NULL REFERENCES recordings(id) ON DELETE CASCADE,
    user_id           TEXT NOT NULL,               -- no FK: history must outlive the account
    user_username     TEXT NOT NULL DEFAULT '',
    user_display_name TEXT NOT NULL DEFAULT '',
    ip                TEXT NOT NULL,
    viewed_at         TEXT NOT NULL
);
INSERT INTO recording_views_new (id, recording_id, user_id, user_username, user_display_name, ip, viewed_at)
    SELECT v.id, v.recording_id, v.user_id, COALESCE(u.username, ''), COALESCE(u.display_name, ''), v.ip, v.viewed_at
    FROM recording_views v LEFT JOIN users u ON u.id = v.user_id;
DROP TABLE recording_views;
ALTER TABLE recording_views_new RENAME TO recording_views;
CREATE INDEX recording_views_recording_idx ON recording_views(recording_id);
