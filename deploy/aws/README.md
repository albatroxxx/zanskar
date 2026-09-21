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

The gateway bootstraps itself from S3: Postgres and guacd in Docker, Caddy with a
Let's Encrypt certificate for `<ip>.sslip.io`, the gateway as a hardened systemd
service on loopback. The master key is generated on the instance and kept at
`/root/zanskar-env.backup`; the SSH keys for the boxes land in `data/` (ignored).
