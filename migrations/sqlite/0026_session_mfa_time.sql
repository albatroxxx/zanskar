-- When a session last proved an authenticator code (ADR 0027). The console
-- command line asks for a fresh code unless this is recent. Sessions that
-- existed before have none, so the first use asks.
ALTER TABLE auth_sessions ADD COLUMN mfa_verified_at TEXT;
