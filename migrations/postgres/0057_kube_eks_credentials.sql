-- An EKS cluster is reached through a role (ADR 0045, 8): the credential type
-- kube_eks names the region, the role Zanskar assumes with the gateway's own
-- AWS identity, the ExternalId its trust policy carries and the cluster, and
-- holds no secret; the token the cluster accepts is minted per session.
ALTER TABLE credentials DROP CONSTRAINT credentials_type_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_type_check
    CHECK (type IN ('password', 'ssh_key', 'ssh_ca', 'domain', 'ec2_instance_connect', 'kube_token', 'kube_client_cert', 'kube_eks'));

ALTER TABLE credentials ADD COLUMN aws_region TEXT;
ALTER TABLE credentials ADD COLUMN aws_role_arn TEXT;
ALTER TABLE credentials ADD COLUMN aws_external_id TEXT;
ALTER TABLE credentials ADD COLUMN eks_cluster TEXT;
