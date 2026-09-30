# Test environment on AWS

A disposable environment for testing Zanskar against real machines: one gateway
in a public subnet (HTTPS from your IP only), a Linux and a Windows target in a
private subnet with no public addresses, and an autoscaling group of Linux
instances behind an internal load balancer for the failover flow.

```
make dist-linux                              # builds dist/zanskar-linux-amd64 with the UI
cd deploy/aws
terraform init
terraform plan -var admin_cidr=$(curl -s https://checkip.amazonaws.com)/32
terraform apply -var admin_cidr=...          # ~5 minutes; Windows takes longer to boot
terraform output                             # URL, IPs, the Windows password command
terraform destroy -var admin_cidr=...        # removes everything, including the bucket
```

## Verifying guided autoscaling enrolment (ADR 0023)

The gateway instance is IMDSv2-only and runs under an instance profile, so this is the
real test of identity detection. With the environment up and the console reachable:

1. **Autoscaling groups** shows the identity card: the principal must read
   `arn:aws:iam::<account>:role/zanskar-test-gateway`, source *detected*. (Apply with
   `-var gateway_principal_override=true` to test the environment-variable override instead;
   the card then says so.)
2. **Enroll group**: region from `terraform output`, group name `<name>-web`, then **Show IAM
   setup**. Run the printed CLI script from a shell with credentials for the account; it
   creates `zanskar-<name>-web` and prints its ARN. (The terraform-made `asg_role_arn` is a
   second valid role for the same group, with the ExternalId in `asg_external_id`; it cannot
   be used here because its trust policy carries a different ExternalId.)
3. Paste the ARN, **Test access**: expect *role works: group found, 2 instances*. To see the
   failure stages, test once before running the script (`assume`) and once with a wrong
   group name (`group`).
4. **Enroll**, then **Sync now**; the instances appear healthy and a session works as before.
5. Delete the role the script made (`aws iam delete-role-policy … && aws iam delete-role …`)
   before `terraform destroy`, since terraform does not know about it.

Two things the bootstrap does not do: the first administrator is created over SSH after boot
(`sudo -i`, then `set -a; . /etc/zanskar/env; set +a; cd /var/lib/zanskar;
ZANSKAR_ADMIN_PASSWORD=… runuser -u zanskar --preserve-environment -- zanskar admin create
--username root --name Admin`), and MFA is required by default, so an API-driven walkthrough
needs `ZANSKAR_REQUIRE_MFA=false` appended to `/etc/zanskar/env` and a restart, or a TOTP
enrolment first.

The gateway bootstraps itself from S3: Postgres and guacd in Docker, Caddy with a
Let's Encrypt certificate for `<ip>.sslip.io`, the gateway as a hardened systemd
service on loopback. The master key is generated on the instance and kept at
`/root/zanskar-env.backup`; the SSH keys for the boxes land in `data/` (ignored).
