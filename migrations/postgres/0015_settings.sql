-- Runtime settings an administrator edits in the console and the gateway
-- applies without a restart, one row per key. The first key is the login
-- banner (system-use notification, NIST AC-8). Boot settings (listen address,
-- database, master key) stay in the environment file.
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by TEXT REFERENCES users(id) ON DELETE SET NULL
);
