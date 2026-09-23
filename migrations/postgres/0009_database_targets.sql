-- Database (PaaS) access targets (ADR 0017): a target may be a managed database
-- endpoint reached with a version-matched client rather than a host. The engine
-- and version identify it; host-oriented columns (host key, TLS pin) stay null.
ALTER TABLE targets ADD COLUMN engine TEXT;
ALTER TABLE targets ADD COLUMN engine_version TEXT;

-- A database target's credential uses the 'database' protocol.
ALTER TABLE target_credentials DROP CONSTRAINT target_credentials_protocol_check;
ALTER TABLE target_credentials ADD CONSTRAINT target_credentials_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database'));
