-- ADR 0021, amended 2026-10-30: a managed-mode gateway can get its
-- certificate from an ACME CA (Let's Encrypt). What the ACME client keeps,
-- the account key and the certificates it ordered with their keys, is
-- stored here sealed like an uploaded certificate's key, so a second
-- gateway on the same database reuses them instead of ordering again.
CREATE TABLE acme_cache (
    cache_key    TEXT PRIMARY KEY,
    data_enc     BLOB NOT NULL,
    key_version  INTEGER NOT NULL REFERENCES key_versions(id),
    updated_at   TEXT NOT NULL
);
