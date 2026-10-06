-- The 30-second step of the last authenticator code accepted for a user. A
-- code at or before it is refused, so each code works once (RFC 6238 5.2).
ALTER TABLE mfa_totp ADD COLUMN last_step BIGINT;
