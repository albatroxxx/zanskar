-- Applications move to the isolated browser (ADR 0034, superseding 0033):
-- there is no proxy, so the per-application label and the sessions table the
-- proxy's cookie needed go, and with them the apps domain setting and the
-- certificate for it. An application keeps its upstream. The protocol CHECKs
-- keep 'http', which is still what a policy grants and a session records;
-- the certificate kind CHECK keeps 'apps' as an allowed value nothing writes,
-- since narrowing it buys nothing.
DROP TABLE app_sessions;
DROP INDEX targets_app_label_live_idx;
ALTER TABLE targets DROP COLUMN app_label;
DELETE FROM settings WHERE key = 'apps.domain';
DELETE FROM tls_certificates WHERE kind = 'apps';
