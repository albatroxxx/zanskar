-- migrate: foreign_keys=off
-- An EKS cluster is reached through a role (ADR 0045, 8): the credential type
-- kube_eks names the region, the role Zanskar assumes with the gateway's own
-- AWS identity, the ExternalId its trust policy carries and the cluster, and
-- holds no secret; the token the cluster accepts is minted per session. The
-- credentials table's CHECK must admit the type, which SQLite cannot alter in
-- place, so the table is rebuilt as 0056 rebuilt it, carrying every column,
-- plus the four the type needs. Other tables reference credentials(id), so
-- foreign keys are off for the rebuild (the framework checks for dangling
-- references after).
CREATE TABLE credentials_new (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL UNIQUE,
    type                    TEXT NOT NULL CHECK (type IN ('password', 'ssh_key', 'ssh_ca', 'domain', 'ec2_instance_connect', 'kube_token', 'kube_client_cert', 'kube_eks')),
    mode                    TEXT NOT NULL CHECK (mode IN ('vaulted', 'user_supplied', 'passthrough')),
    username                TEXT,
    domain                  TEXT,
    secret_enc              BLOB,
    public_key              TEXT,
    key_version             INTEGER REFERENCES key_versions(id),
    created_by              TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    rotated_at              TEXT,
    certificate_ttl_seconds INTEGER,
    certificate_principals  TEXT NOT NULL DEFAULT '[]',
    pending_secret_enc      BLOB,
    pending_public_key      TEXT,
    pending_key_version     INTEGER REFERENCES key_versions(id),
    pending_created_at      TEXT,
    retired_public_key      TEXT,
    retired_at              TEXT,
    aws_region              TEXT,
    aws_role_arn            TEXT,
    aws_external_id         TEXT,
    eks_cluster             TEXT
);
INSERT INTO credentials_new (id, name, type, mode, username, domain, secret_enc, public_key, key_version, created_by, created_at, updated_at, rotated_at,
        certificate_ttl_seconds, certificate_principals, pending_secret_enc, pending_public_key, pending_key_version, pending_created_at, retired_public_key, retired_at)
    SELECT id, name, type, mode, username, domain, secret_enc, public_key, key_version, created_by, created_at, updated_at, rotated_at,
        certificate_ttl_seconds, certificate_principals, pending_secret_enc, pending_public_key, pending_key_version, pending_created_at, retired_public_key, retired_at
    FROM credentials;
DROP TABLE credentials;
ALTER TABLE credentials_new RENAME TO credentials;
