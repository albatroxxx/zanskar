-- Database (PaaS) access targets (ADR 0017): a target may be a managed database
-- endpoint reached with a version-matched client rather than a host. The engine
-- and version identify it; host-oriented columns (host key, TLS pin) stay null.
ALTER TABLE targets ADD COLUMN engine TEXT;
ALTER TABLE targets ADD COLUMN engine_version TEXT;

-- SQLite cannot alter a column CHECK in place, so target_credentials is rebuilt
-- to allow the 'database' protocol. It is a leaf table (nothing references it),
-- so the rebuild is safe with foreign keys enabled.
CREATE TABLE target_credentials_new (
    target_id      TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    protocol       TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database')),
    credential_id  TEXT NOT NULL REFERENCES credentials(id) ON DELETE RESTRICT,
    PRIMARY KEY (target_id, protocol)
);
INSERT INTO target_credentials_new (target_id, protocol, credential_id)
    SELECT target_id, protocol, credential_id FROM target_credentials;
DROP TABLE target_credentials;
ALTER TABLE target_credentials_new RENAME TO target_credentials;
