-- The certificate from Let's Encrypt is withdrawn (ADR 0021's amendment of
-- 2026-10-30, withdrawn 2026-11-03): the owner wanted one place to install
-- and replace a certificate, which the TLS certificate card is; a
-- certificate from an ACME CA is a proxy's business (Caddy, nginx). The
-- account key and certificates the gateway cached go with it.
DROP TABLE IF EXISTS acme_cache;
