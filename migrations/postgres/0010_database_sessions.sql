-- Allow the 'database' protocol for access sessions (ADR 0017), so a brokered
-- database session records like any other.
ALTER TABLE access_sessions DROP CONSTRAINT access_sessions_protocol_check;
ALTER TABLE access_sessions ADD CONSTRAINT access_sessions_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database'));
