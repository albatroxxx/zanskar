-- One mail server for every email channel (ADR 0039, amended 2026-11-03,
-- later): the SMTP host, port, account and sender, set once under Settings,
-- the password sealed with the key ring. One row, id 1. A channel keeps its
-- recipients alone; the gateway adopts the first channel's server at start
-- when none is set yet.
CREATE TABLE email_server (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL,
    username     TEXT NOT NULL,
    from_address TEXT NOT NULL,
    password_enc BYTEA,
    key_version  INTEGER REFERENCES key_versions(id),
    updated_at   TIMESTAMPTZ NOT NULL
);
