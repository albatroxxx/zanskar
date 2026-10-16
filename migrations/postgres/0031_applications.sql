-- Applications (ADR 0033): an application is a target with an upstream the
-- gateway's proxy forwards to and a label it is served at under the apps
-- domain. Policies grant it under the protocol 'http', so the protocol CHECKs
-- of access_sessions and access_requests widen. The gateway holds a second TLS
-- certificate for the apps domain (kind 'apps'). app_sessions ties a browser's
-- per-application cookie to the access session it opened and the sign-in it
-- came from.
ALTER TABLE targets ADD COLUMN app_upstream TEXT;
ALTER TABLE targets ADD COLUMN app_label TEXT;
CREATE UNIQUE INDEX targets_app_label_live_idx ON targets(app_label) WHERE deleted_at IS NULL AND app_label IS NOT NULL;

ALTER TABLE access_sessions DROP CONSTRAINT access_sessions_protocol_check;
ALTER TABLE access_sessions ADD CONSTRAINT access_sessions_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http'));

ALTER TABLE access_requests DROP CONSTRAINT access_requests_protocol_check;
ALTER TABLE access_requests ADD CONSTRAINT access_requests_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http'));

ALTER TABLE tls_certificates DROP CONSTRAINT tls_certificates_kind_check;
ALTER TABLE tls_certificates ADD CONSTRAINT tls_certificates_kind_check
    CHECK (kind IN ('uploaded', 'generated', 'apps'));

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
    expires_at       TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL,
    last_seen_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX app_sessions_session_idx ON app_sessions(session_id);
