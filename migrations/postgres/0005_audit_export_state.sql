-- Checkpoint per SIEM sink so audit export is at-least-once across restarts.
CREATE TABLE audit_export_state (
    sink        TEXT PRIMARY KEY,
    last_id     BIGINT NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL
);
