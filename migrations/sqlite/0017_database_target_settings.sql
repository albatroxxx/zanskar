-- Database targets (ADR 0017) name the database to open and how the sidecar
-- protects the upstream connection: tls_mode is disable | prefer | require |
-- verify-full, tls_ca holds an optional PEM bundle for verify-full (for
-- example the provider's CA). Hosts leave all three empty.
ALTER TABLE targets ADD COLUMN database_name TEXT;
ALTER TABLE targets ADD COLUMN tls_mode TEXT;
ALTER TABLE targets ADD COLUMN tls_ca TEXT;
