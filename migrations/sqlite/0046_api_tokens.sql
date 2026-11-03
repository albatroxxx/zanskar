-- API tokens (ADR 0044): an administrator's credential for automation, the
-- Terraform provider and scripts, scoped to the configuration API. The token
-- is shown once; only its SHA-256 is kept (token_hash), with its first
-- characters (prefix) to tell tokens apart in a list. A token lapses at
-- expires_at, ends at revoked_at, and goes with its owner.
CREATE TABLE api_tokens (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    prefix        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    last_used_at  TEXT,
    revoked_at    TEXT
);
CREATE INDEX api_tokens_user ON api_tokens (user_id);
