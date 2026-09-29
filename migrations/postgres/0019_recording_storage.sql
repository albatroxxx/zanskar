-- Recording storage configured from the console (ADR 0020): one row with
-- the S3 settings and, when static keys are used, the secret sealed by the
-- key ring. Absent, the environment's settings or the local directory apply.
CREATE TABLE recording_storage (
    id             TEXT PRIMARY KEY CHECK (id = 'active'),
    bucket         TEXT NOT NULL,
    prefix         TEXT NOT NULL,
    region         TEXT NOT NULL DEFAULT '',
    endpoint       TEXT NOT NULL DEFAULT '',
    kms_key_id     TEXT NOT NULL DEFAULT '',
    auth           TEXT NOT NULL CHECK (auth IN ('role', 'keys')),
    access_key_id  TEXT NOT NULL DEFAULT '',
    secret_enc     BYTEA,
    key_version    INTEGER REFERENCES key_versions(id),
    updated_by     TEXT REFERENCES users(id) ON DELETE SET NULL,
    updated_at     TIMESTAMPTZ NOT NULL
);
