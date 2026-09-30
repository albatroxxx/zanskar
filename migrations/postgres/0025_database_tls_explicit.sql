-- Database targets are verified by default from here on (ADR 0025): a target
-- that names no TLS mode gets verify-full. Targets that existed before took
-- prefer when they named none, so that is written into them explicitly;
-- upgrading changes nothing about how an existing target connects.
UPDATE targets SET tls_mode = 'prefer'
WHERE engine IS NOT NULL AND engine <> '' AND (tls_mode IS NULL OR tls_mode = '');
