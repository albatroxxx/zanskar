-- SSH certificate authority as the recommended Linux path (ADR 0022): each
-- ssh_ca credential can set the lifetime of the certificates it mints and
-- the login users it will mint them for. NULL and '[]' keep today's
-- behaviour: five minutes, any login user.
ALTER TABLE credentials ADD COLUMN certificate_ttl_seconds INTEGER;
ALTER TABLE credentials ADD COLUMN certificate_principals TEXT NOT NULL DEFAULT '[]';
