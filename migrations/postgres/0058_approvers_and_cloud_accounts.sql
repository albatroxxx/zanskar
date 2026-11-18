-- Approvers (ADR 0049): a fourth role, approver, which the user_roles CHECK
-- must admit; and a request a person may withdraw, status cancelled, which
-- the access_requests CHECK must admit. Cloud accounts (ADR 0050): a role in
-- an AWS account is a target, derived from cloud_role_arn as a cluster is
-- from its API server; it serves one protocol, cloud, which the three
-- protocol CHECKs must admit.
ALTER TABLE targets ADD COLUMN cloud_platform TEXT;
ALTER TABLE targets ADD COLUMN cloud_account_id TEXT;
ALTER TABLE targets ADD COLUMN cloud_account_alias TEXT;
ALTER TABLE targets ADD COLUMN cloud_role_arn TEXT;
ALTER TABLE targets ADD COLUMN cloud_external_id TEXT;
ALTER TABLE targets ADD COLUMN cloud_max_minutes INTEGER;
ALTER TABLE targets ADD COLUMN cloud_region TEXT;

ALTER TABLE user_roles DROP CONSTRAINT user_roles_role_check;
ALTER TABLE user_roles ADD CONSTRAINT user_roles_role_check
    CHECK (role IN ('admin', 'auditor', 'approver', 'user'));

ALTER TABLE target_credentials DROP CONSTRAINT target_credentials_protocol_check;
ALTER TABLE target_credentials ADD CONSTRAINT target_credentials_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http', 'kube', 'pod', 'cloud'));

ALTER TABLE access_sessions DROP CONSTRAINT access_sessions_protocol_check;
ALTER TABLE access_sessions ADD CONSTRAINT access_sessions_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http', 'kube', 'pod', 'cloud'));

ALTER TABLE access_requests DROP CONSTRAINT access_requests_protocol_check;
ALTER TABLE access_requests ADD CONSTRAINT access_requests_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http', 'kube', 'pod', 'cloud'));

ALTER TABLE access_requests DROP CONSTRAINT access_requests_status_check;
ALTER TABLE access_requests ADD CONSTRAINT access_requests_status_check
    CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'revoked', 'cancelled'));
