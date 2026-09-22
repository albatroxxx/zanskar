-- Recording retention (ADR 0015). A single, admin-editable policy: keep by age
-- (max_age_days) with a total-size backstop (max_total_bytes); 0 disables that
-- dimension. purged_at marks a recording whose blob the sweeper deleted while
-- its metadata row stays, because audit events reference the recording id.
CREATE TABLE retention_policy (
    id              TEXT PRIMARY KEY,
    max_age_days    INTEGER NOT NULL DEFAULT 0,
    max_total_bytes BIGINT  NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ,
    updated_by      TEXT
);

ALTER TABLE recordings ADD COLUMN purged_at TIMESTAMPTZ;
CREATE INDEX recordings_purge_idx ON recordings(purged_at, finished_at);
