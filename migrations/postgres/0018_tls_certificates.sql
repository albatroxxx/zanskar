-- The gateway's own TLS certificate, managed from the console (ADR 0021).
-- One row per kind: 'uploaded' (an administrator's certificate) and
-- 'generated' (the self-signed one made at first start). The private key is
-- envelope-encrypted like every other secret; the certificate is public.
CREATE TABLE tls_certificates (
    kind         TEXT PRIMARY KEY CHECK (kind IN ('uploaded', 'generated')),
    cert_pem     TEXT NOT NULL,
    key_enc      BYTEA NOT NULL,
    key_version  INTEGER NOT NULL REFERENCES key_versions(id),
    created_by   TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL
);
