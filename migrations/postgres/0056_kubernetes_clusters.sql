-- A Kubernetes cluster is a target (ADR 0045, built under ADR 0048): its API
-- server's URL makes it one, as an engine makes a database and an upstream
-- an application. It serves two protocols, kube (the API, through the
-- gateway as the person) and pod (a shell into a container), which the
-- protocol CHECKs must admit. A cluster binds a credential of two new
-- types, kube_token and kube_client_cert, which the credentials table's own
-- CHECK must admit.
ALTER TABLE targets ADD COLUMN kube_api_server TEXT;
ALTER TABLE targets ADD COLUMN kube_ca TEXT;
ALTER TABLE targets ADD COLUMN kube_impersonate INTEGER;
ALTER TABLE targets ADD COLUMN kube_platform TEXT;

ALTER TABLE credentials DROP CONSTRAINT credentials_type_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_type_check
    CHECK (type IN ('password', 'ssh_key', 'ssh_ca', 'domain', 'ec2_instance_connect', 'kube_token', 'kube_client_cert'));

ALTER TABLE target_credentials DROP CONSTRAINT target_credentials_protocol_check;
ALTER TABLE target_credentials ADD CONSTRAINT target_credentials_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http', 'kube', 'pod'));

ALTER TABLE access_sessions DROP CONSTRAINT access_sessions_protocol_check;
ALTER TABLE access_sessions ADD CONSTRAINT access_sessions_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http', 'kube', 'pod'));

ALTER TABLE access_requests DROP CONSTRAINT access_requests_protocol_check;
ALTER TABLE access_requests ADD CONSTRAINT access_requests_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'winrm', 'database', 'http', 'kube', 'pod'));
