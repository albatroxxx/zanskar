-- Where the gateway sends word of what happened (ADR 0039): a signed webhook
-- or email, each asking for kinds of event. config holds what is not secret
-- (the webhook's host, the SMTP server, sender and recipients); the webhook
-- URL, its signing key and the SMTP password are sealed in secret_enc under
-- key_version. A channel's place in the audit log is its row in
-- audit_export_state, sink 'notify:<id>'.
CREATE TABLE notification_channels (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    kind         TEXT NOT NULL CHECK (kind IN ('webhook', 'email')),
    events       JSONB NOT NULL,
    config       JSONB NOT NULL,
    secret_enc   BYTEA,
    key_version  INTEGER REFERENCES key_versions(id),
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL
);
