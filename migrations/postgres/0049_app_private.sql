-- An application's private dependencies (ADR 0037, amended 2026-11-03,
-- later): the private networks (CIDRs) and hosts (host:port) its pages may
-- load from beside its origins, under "any public address". JSON:
-- {"networks": [...], "hosts": [...]}; NULL for none, and for a host or a
-- database.
ALTER TABLE targets ADD COLUMN app_private JSONB;
