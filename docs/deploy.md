# Deploying Zanskar

Zanskar is one static binary (the web UI is embedded) plus a PostgreSQL database and,
for RDP and VNC, a guacd sidecar. This guide covers a single node with Docker Compose
and a highly available Kubernetes deployment with the Helm chart in `deploy/helm/zanskar`.

## Topology

```
 browsers ──TLS──▶ load balancer / ingress ──TLS──▶ zanskar gateways (N pods)
                                                   │        │        │
                                                   │        │        └──▶ targets: SSH 22, WinRM 5986
                                                   │        └──▶ guacd (ClusterIP, isolated) ──▶ targets: RDP 3389, VNC 5900
                                                   └──▶ PostgreSQL          recordings: shared volume or S3
                                                        cloud APIs (autoscaling groups, via the pod identity)
```

- **Gateways** are stateless apart from two in-memory structures described under
  High availability. Everything durable is in PostgreSQL and the recordings store.
- **guacd** must only be reachable from gateway pods. It speaks an unauthenticated
  protocol and carries target credentials in flight (threat model, ADR 0002).
- **Recordings** are append-only files. Use a ReadWriteMany volume shared by all
  gateways, or object storage (an S3-compatible bucket, set at install or from the console's Settings
  page; see Recording storage below).

## Packages (deb / rpm)

Tagged releases publish `.deb` and `.rpm` packages plus `linux/amd64` and `linux/arm64`
tarballs, each listed in `SHA256SUMS`, on the GitHub releases page. The package installs
the `zanskar` binary to `/usr/bin`, a hardened systemd unit, and `/etc/zanskar/env.example`;
it creates the `zanskar` service user and `/var/lib/zanskar` but does **not** start the
service, since it has no configuration yet.

```sh
# Debian / Ubuntu
sudo apt update && sudo apt install ./zanskar_<version>_linux_amd64.deb
# RHEL / Fedora / SUSE
sudo dnf makecache && sudo rpm -i zanskar_<version>_linux_amd64.rpm

sudo zanskar init          # writes /etc/zanskar/env and prints the exact next commands

# Create the first admin as the service user so it owns the SQLite database —
# `zanskar init` prints this line with your paths filled in. admin create
# prompts for the password twice without echo; keep it off the command line
# (shell history). Scripts can export ZANSKAR_ADMIN_PASSWORD from `read -rs`.
sudo bash -c 'set -a; . /etc/zanskar/env; set +a; \
  runuser -u zanskar -- zanskar migrate && \
  runuser -u zanskar -- zanskar admin create --username admin --name "Your Name"'

sudo systemctl enable --now zanskar
```

**RDP and VNC need guacd, which the package does not install.** Start the official
container on loopback only (guacd is unauthenticated; never publish it wider), then set
`ZANSKAR_GUACD_ADDR=127.0.0.1:4822` (or pass `-guacd` to `init`) and restart, or set the
guacd address on the console's Settings page, which applies without a restart:

```sh
sudo docker run -d --name guacd --restart unless-stopped -p 127.0.0.1:4822:4822 \
  -e HOME=/tmp --read-only --tmpfs /tmp:size=512m,mode=1777 guacamole/guacd:1.6.0
```

**TLS without a certificate.** The gateway refuses plain HTTP on a non-loopback address.
On a host with a public IP and 80/443 open, Caddy plus a `<ip-with-dashes>.sslip.io` name
gives a real Let's Encrypt certificate with no domain of your own (the AWS reference
deployment does exactly this):

```sh
IP=$(curl -s https://api.ipify.org); HOST=${IP//./-}.sslip.io
sudo tee /etc/caddy/Caddyfile >/dev/null <<CADDY
$HOST {
  encode zstd gzip
  reverse_proxy 127.0.0.1:8443
}
CADDY
sudo systemctl enable --now caddy
sudo zanskar init -non-interactive -behind-proxy -guacd 127.0.0.1:4822
```

Run the database commands as the `zanskar` service user (the `runuser` wrapper above):
with the default SQLite backend, files created by root would be unwritable by the service.
Verify a download before installing: `sha256sum -c SHA256SUMS --ignore-missing`. Put a
TLS-terminating reverse proxy in front — the unit binds loopback by default. Upgrades keep
`/var/lib/zanskar` (database and recordings) and your `/etc/zanskar/env`; removal leaves
them in place. Build the packages locally with `make packages` (needs goreleaser).

## Guided single-node install

For a single instance, `zanskar init` writes the environment file the server reads
(ADR 0014): it asks for the listen address and TLS mode (own certificate, or behind a
TLS proxy on loopback), the data directory, whether to enable RDP and VNC, MFA and
logging; it generates the master key and prints the migrate and admin-create steps. It
runs non-interactively from flags for cloud-init or Ansible, and re-running it preserves
an existing master key.

```sh
sudo zanskar init                                              # interactive, writes /etc/zanskar/env
zanskar init --print --behind-proxy --data-dir /var/lib/zanskar   # preview to stdout
```

The rest of this guide sets the same variables by hand, for Docker Compose and Kubernetes.

## Single node with Docker Compose

`deploy/docker-compose.yml` is the single-instance stack: the gateway on SQLite with a
persistent volume, `guacd` for RDP/VNC, and Caddy terminating TLS in front. The gateway
port is never published — only Caddy's 80/443 are — so plaintext flows only on the
private Docker network between them. A one-shot `zanskar-migrate` service applies pending
migrations before the gateway starts (`serve` refuses to run with migrations pending).

The stack pulls the published image `ghcr.io/albatroxxx/zanskar:${ZANSKAR_VERSION:-latest}`
(linux/amd64 and linux/arm64, signed with Sigstore — verification commands are in each
release's notes; `cosign` is not in the Ubuntu, Debian or RHEL repositories, so install it from
[its own release](https://github.com/sigstore/cosign/releases/latest) first). `latest` only ever points at a stable release; to run a release candidate
set `ZANSKAR_VERSION` explicitly in `deploy/.env`.

```sh
cp deploy/.env.example deploy/.env    # then set ZANSKAR_MASTER_KEY (openssl rand -base64 32)
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml exec -e ZANSKAR_ADMIN_PASSWORD=... \
  zanskar /zanskar admin create --username admin --name "Your Name"
```

To build the image from a checkout instead (contributors, unreleased changes), add the
override file: `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.build.yml up -d --build`.

By default Caddy serves `https://localhost/` with a self-signed certificate from its
internal CA (a browser warning, fine for a trial). For a real certificate, set
`ZANSKAR_SITE_ADDRESS` to a public hostname in `deploy/.env` and make ports 80 and 443
reachable with DNS pointing at the host; Caddy fetches one from Let's Encrypt
automatically. The gateway trusts Caddy's `X-Forwarded-*` headers — so the audit log
records real client IPs — via `ZANSKAR_TRUST_PROXY_TLS` and the pinned `172.28.0.0/16`
network in `ZANSKAR_TRUSTED_PROXIES`; if that subnet collides with an existing network,
change it in both places in the compose file.

The SQLite database and local recordings live in the `zanskar_data` volume; back them up
with `zanskar backup` (see [Backups and key custody](#backups-and-key-custody)) or by
snapshotting the volume. To exercise the PostgreSQL path instead, use
`deploy/docker-compose.dev.yml` — a plaintext-on-loopback development stack, not for
production.

## Kubernetes with the Helm chart

> **Preview.** The chart installs and runs, but 1.2 is a single-instance release: the
> cross-pod control channel that admin terminate and auditor shadowing need with more than
> one replica is Phase 4 work. Run it with `replicaCount: 1` and treat it as an evaluation
> path until HA is announced. `image.tag` defaults to the chart's `appVersion`, which tracks
> the current release tag.

Prerequisites: a PostgreSQL 14+ database, a `kubernetes.io/tls` certificate for the
pods (cert-manager is the easy path), an ingress controller that supports WebSockets
and cookie affinity, and, for recordings with more than one replica, a ReadWriteMany
storage class or an S3 bucket.

1. **Secrets.** The chart reads `ZANSKAR_MASTER_KEY` and `ZANSKAR_DB_DSN` from an existing
   Secret and never writes secrets from values:

   ```sh
   kubectl create secret generic zanskar-secrets \
     --from-literal=ZANSKAR_MASTER_KEY="$(zanskar keygen)" \
     --from-literal=ZANSKAR_DB_DSN="postgres://zanskar:PASSWORD@db:5432/zanskar?sslmode=require"
   ```

2. **TLS in the pod.** Set `tls.secretName` to a `kubernetes.io/tls` Secret. It is mounted
   at `/tls` and wired to `ZANSKAR_TLS_CERT`/`ZANSKAR_TLS_KEY`. Terminating TLS at the
   ingress alone is not enough: the pod itself refuses to listen on plain HTTP. Use the
   ingress `backend-protocol: HTTPS` annotation (set in the default values) so the
   ingress re-encrypts to the pod.

3. **Install.**

   ```sh
   helm install zanskar deploy/helm/zanskar -n zanskar --create-namespace \
     -f my-values.yaml
   ```

   A pre-install/pre-upgrade hook Job runs `zanskar migrate`; the gateway refuses to
   start with migrations pending, so upgrades are a single `helm upgrade`.

4. **First admin.** There is no bootstrap endpoint on purpose:

   ```sh
   kubectl -n zanskar exec -it deploy/zanskar -- /zanskar admin create --username admin --name "Your Name"
   ```

5. **Autoscaling groups on EKS (IRSA).** Give the gateway pods an IAM role by annotating
   the service account (`serviceAccount.annotations: eks.amazonaws.com/role-arn: ...`).
   That role is the principal that assumes each group's cross-account role with the
   ExternalId Zanskar generated; set `config.awsGatewayPrincipal` to the same ARN so the
   trust policy shown to admins is correct. The per-group role needs only the
   permissions the admin UI renders (Describe calls, console output, Instance Connect).

6. **Ingress affinity.** Two requests must land on the same pod: `POST /api/v1/connect`,
   which issues a short-lived ticket held in that pod's memory, and the `GET /ws/*`
   upgrade that redeems it within 30 seconds. Behind an ingress, client IPs are NATed,
   so use cookie affinity; the default values carry the ingress-nginx annotations
   (`affinity: cookie`, `session-cookie-name: zanskar_pod`, one-hour proxy timeouts for
   long WebSocket sessions). The Service defaults to `sessionAffinity: ClientIP` for
   setups without an ingress.

## High availability

Run two or more gateway replicas behind the ingress. What lives where:

| State | Location | Shared across pods |
|---|---|---|
| Users, policies, targets, credentials (sealed), audit chain, sessions | PostgreSQL | yes |
| Recordings | RWX volume or S3 | yes |
| Connect tickets (30 s, single use) | pod memory | no, hence affinity |
| Live-session registry (what is connected right now) | pod memory | no |
| Autoscaling sync loop | every pod runs it | duplicated polls, idempotent writes |

Consequences, stated plainly:

- **Admin "terminate" and auditor "shadow" act on the pod that receives the request.**
  If the session lives on another pod, terminate closes the database row (the session
  shows as ended) but the live connection keeps running until its own bridge notices,
  and shadow returns "not live here". With cookie affinity an admin who terminates a
  session usually lands on a different pod than the user. Mitigations today: run a
  single gateway replica where live control matters, or put admins behind their own
  pod via the separate admin listener. A cross-pod control channel (Postgres LISTEN/
  NOTIFY or a small pub/sub) is the planned fix and is tracked in the roadmap.
- **Autoscaling sync runs on every pod.** Polls are duplicated; the writes are
  idempotent upserts, so this costs API calls, not correctness. A leader election is a
  follow-up.
- The audit chain is serialised with a database advisory lock, so many pods appending
  concurrently stay consistent (ADR 0008).

## Upgrades and migrations

Migrations are explicit and forward-only. The chart's hook Job applies them before the
new pods start; outside Helm, run `zanskar migrate` yourself before restarting. Take a
database backup first. Rolling updates keep at least one pod (PodDisruptionBudget);
`terminationGracePeriodSeconds` gives live sessions a minute to close.

## Backups and key custody

For the single-node SQLite deployment (the default), `zanskar backup` writes a
consistent snapshot without stopping the service. It reads the same `ZANSKAR_*`
environment as the server:

```
zanskar backup --out /secure/zanskar-$(date +%F).tar.gz
```

It snapshots the database with SQLite's `VACUUM INTO` — a single transactional copy that
is safe to take while the gateway is running — and includes the local recordings
directory. When recordings live in S3 the archive records the backend instead of copying
them; the object store is their backup. The **master key is never written to the
archive**, only a fingerprint of it, so restore can warn on a mismatch.

Restore into a stopped service, then start it:

```
systemctl stop zanskar
zanskar restore --in /secure/zanskar-2026-09-22.tar.gz --force
systemctl start zanskar
```

Restore refuses to overwrite an existing database without `--force`, and warns when the
archive was sealed under a different `ZANSKAR_MASTER_KEY` — its stored credentials would
be undecryptable. Restore the original key first if you have it. For PostgreSQL, use the
tooling below rather than `zanskar backup`.

- **PostgreSQL**: regular dumps or PITR. The audit chain, recordings index and every
  sealed secret live here.
- **Recordings**: back up the volume or bucket; the database rows reference them by URI
  and carry their SHA-256 for integrity checks.
- **`ZANSKAR_MASTER_KEY`**: escrow it in a vault the database backup cannot reach. Every
  vaulted credential, identity-provider secret and authenticator secret is sealed under
  keys wrapped by it (ADR 0007). Without it a restored database is a list of ciphertext.
  Rotating it is supported by the key ring (`key_versions`); losing it is not.

## Security checklist

- TLS on the pod (`tls.secretName`) and on the ingress; HSTS is sent automatically when
  the gateway serves TLS.
- guacd isolated by the NetworkPolicy the chart installs; never expose port 4822.
- `ZANSKAR_REQUIRE_MFA=true` (default). Do not turn it off outside throwaway installs.
  The console's Settings page can override it; the change is audited and shows its source.

## TLS certificate

`ZANSKAR_TLS_MODE` picks how the listener is protected (ADR 0021):

- `managed`: Zanskar serves TLS itself with a certificate it manages. At first start it
  makes a self-signed one for the listen host, the machine's host name and its addresses;
  browsers warn until a real certificate is uploaded on the console's Settings page (PEM
  certificate chain and unencrypted key). The upload applies to the next connection, no
  restart, and can be removed again. The SHA-256 the gateway logs at start and shows in
  Settings is what to check on the first visit. `zanskar init -managed-tls` writes this mode.
- `file`: the certificate in `ZANSKAR_TLS_CERT` / `ZANSKAR_TLS_KEY`. A console upload takes
  precedence over the file while it is set.
- `proxy`: plain HTTP on loopback behind a TLS-terminating proxy; the certificate is the
  proxy's business and the Settings card says so.

Unset, the mode is `file` when a certificate is configured and `proxy` otherwise, so an
existing install keeps its behaviour.

**The default install is managed TLS on `0.0.0.0:443` with `ZANSKAR_HTTP_REDIRECT_ADDR=:80`**:
a plain-HTTP listener that answers every request with a redirect to the HTTPS listener
(the same path, the TLS port added when it is not 443). `zanskar init -behind-proxy` keeps
the old shape, loopback 8443 behind a proxy. The packaged unit grants
`CAP_NET_BIND_SERVICE` so the unprivileged service can bind 443 and 80; a hand-written unit
needs `AmbientCapabilities=CAP_NET_BIND_SERVICE` and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`,
and the gateway says so when a bind on a port below 1024 is refused. HSTS is sent whenever
the gateway serves TLS; browsers ignore it on a connection with certificate errors, so the
self-signed default pins nothing until a real certificate is uploaded.

**The redirect only targets a name the served certificate covers.** A redirect to a name the
certificate cannot serve moves the browser warning one hop instead of fixing it, so a request
whose `Host` is not covered is answered with a short page explaining what to change. The
generated certificate covers what the machine can work out for itself: `localhost`, its host
name, and its interface addresses. On a cloud instance the public address is translated
upstream and is on no interface, so name it with `ZANSKAR_TLS_HOSTS` (comma separated;
`zanskar init` asks, `-tls-hosts` sets it non-interactively). Adding a name and restarting
regenerates the self-signed certificate so it carries it; an uploaded or file certificate is
never touched.

## Recording storage

Recordings go to the local directory by default. To keep them in an S3-compatible bucket,
open the console's **Settings → Recording storage** card: bucket, key prefix, region,
endpoint (MinIO, Ceph), KMS key and either the instance role or a static access key (the
secret is sealed by the master key). **Test** writes, reads back and deletes a probe object;
**Save and use** does the same and then makes the bucket active for the next session, no
restart. **Move** copies existing local recordings into the bucket in the background,
checking each digest, and removes the local files. The `ZANSKAR_RECORDINGS_S3_*` variables
remain the install-time default; a console setting overrides them and can be removed again.
Recordings are always read from where they were written, so changing the prefix is safe;
changing the bucket leaves earlier recordings unreachable until that bucket is configured
again, and the card says so. The gateway refuses to start when a stored storage
configuration cannot be built or its secret unsealed (recordings must not quietly go
elsewhere); the way out is `DELETE FROM recording_storage;` in the database, then start.

### Retention

Recordings are deleted by an audited hourly sweep. The global policy on the console's
**Retention** page sets a maximum age and a total size. A **policy** and a **target** can each
carry `retention_days` of their own; the longest retention among the policies that granted a
session applies, and a target's value wins over that. The value is fixed on each recording when
its session starts, so changing a policy later does not shorten what was already promised.

## Database access

Database targets (PostgreSQL, MySQL, MariaDB, including RDS) are reached through an
ephemeral per-session client container beside a credential-holding sidecar on a private
per-session network (ADR 0017): pgbouncer for PostgreSQL, the gateway's own image running
`zanskar dbproxy` for MySQL and MariaDB. The container the user types into never holds the
password.

- **The gateway host needs Docker or Podman**, and the `zanskar` service user must be able
  to use it. The packaged unit does not grant this by itself (the Docker socket is
  root-equivalent, and the unit must keep starting on hosts without Docker). On a host that
  serves database targets, add a drop-in and restart:

  ```sh
  sudo systemctl edit zanskar   # opens an override file; add:
  [Service]
  SupplementaryGroups=docker
  ```

  For Podman, point `ZANSKAR_DOCKER_PATH` at the `podman` binary.
- **Images pulled on first use:** `postgres:<version>-alpine` and `edoburu/pgbouncer` for
  PostgreSQL; `mysql:<version>` or `mariadb:<version>` and `ghcr.io/albatroxxx/zanskar:<your
  version>` for MySQL and MariaDB. Pull them ahead of time on an air-gapped host; the relay
  image can be pointed at a mirror with `ZANSKAR_DBPROXY_IMAGE` or the console's Settings
  page.
- **TLS to the database** is negotiated when the server offers it and not verified yet
  (pgbouncer `server_tls_sslmode=prefer`; the MySQL relay behaves the same). Certificate
  verification arrives with the target's TLS settings.
- Not available inside the Compose stack; use the package install for database targets.

## Autoscaling groups on AWS

Zanskar reads an autoscaling group through a role in your AWS account that only this gateway
can assume (ADR 0011, 0023). Enrolment is guided from **Autoscaling groups → Enroll group**:

1. **The gateway's identity.** The page shows the principal this gateway runs as. On EC2
   with an instance profile, or on EKS with IRSA, it is detected at start from STS and
   converted to the role ARN a trust policy needs. Nothing else is required. A gateway
   outside AWS, or one that should present a different principal, sets
   `ZANSKAR_AWS_GATEWAY_PRINCIPAL=arn:aws:iam::<account>:role/<role>` in the environment
   file; the variable always wins over detection. Until a principal is known, the console
   says so and withholds the trust policy rather than printing a placeholder.
2. **Show IAM setup.** With the region and the group's name filled in, the console mints the
   ExternalId and shows a paste-ready AWS CLI script that creates the role with the trust
   policy and the read-only permissions policy, the same role as a CloudFormation template,
   and the two policy documents on their own.
3. **Test access.** Paste the role's ARN and test: the gateway assumes the role with the
   ExternalId and describes the group. A failure names the stage: the trust policy (wrong
   principal or ExternalId), the permissions policy, or no group by that name in that
   region. The test is audited as `asg.test`.
4. **Enroll.** The saved group carries the ExternalId the role was created with. A saved
   group can be tested again from its drawer at any time.

**The gateway's own role needs the other half of the handshake.** Assuming a role takes
two permissions: the customer's role must trust the gateway's principal (the trust policy
above), and the gateway's own role must be allowed to call `sts:AssumeRole` on that role
ARN, through an identity policy on the gateway's instance profile or IRSA role. Without the
second, the access test fails at the `assume` stage with the same message as a wrong trust
policy. In the same account this is usually already granted; across accounts it never is.

Zanskar never stores AWS access keys; the gateway's own credentials come from the SDK's
default chain, and the customer's role is the only thing it assumes.

## SSH without stored keys: the certificate authority

The recommended way to reach Linux targets is an **SSH certificate authority** credential
(ADR 0022). Zanskar holds one CA key, sealed by the master key, and mints a certificate per
session that lives for minutes; the person connecting never sees it and the target stores
nothing per gateway. Static SSH keys keep working and remain the fallback.

1. **Credentials → Add credential → SSH certificate authority.** Leave the key blank and
   Zanskar generates an ed25519 authority. Leave *Login user* blank so each person logs in as
   their own Zanskar username, or set one account (say `deploy`) for everyone.
2. **Install the trust on each target**, as root. The console prints these with the real key:

   ```sh
   echo 'ssh-ed25519 AAAA... zanskar-ca' > /etc/ssh/zanskar_ca.pub
   echo 'TrustedUserCAKeys /etc/ssh/zanskar_ca.pub' > /etc/ssh/sshd_config.d/zanskar.conf
   systemctl reload ssh 2>/dev/null || systemctl reload sshd
   ```

   An sshd without `sshd_config.d` takes the `TrustedUserCAKeys` line in
   `/etc/ssh/sshd_config`. For autoscaling groups put the same lines in the launch
   template's user data.
3. **Bind the credential** to the target's SSH slot, probe and trust the host key as usual.

Each certificate is valid for exactly one login user, permits a PTY and nothing else, lives
`certificate_ttl_seconds` (default 300, at most 3600; it only has to outlive the handshake),
and carries the key id `zanskar:<zanskar user>:<login user>:<time>`. sshd logs that id on
every accepted login, so the target's own auth log names the Zanskar user behind a shared
account. The credential's **Allowed login users** list limits which login users it will
issue for; a connect for anyone else is refused with `login_user_not_permitted` before a
certificate exists, and audited.

**Rotating the authority** is two steps in the credential's Setup panel, so no session
breaks on a host that has not learned the new key yet: *Prepare next key* generates and
seals a second key, and the install commands now write both public keys; **Test** each
bound target with the next key (a real one-off login, visible in the target's auth log as
`zanskar-probe:<admin>:<login user>`); *Cut over* once they all pass, after which sessions
use the new key and the old private key is gone; then remove the old public key from
targets and confirm. There is no timer: rotate when the key may have been exposed or when
policy says so. Windows and database passwords are not rotated by Zanskar; leave that to the
system that owns the account.

## Changing boot settings and restarting

Listen address, TLS files, database, master key, recordings storage and the other
install-time variables are read once at start. Edit `/etc/zanskar/env`, and the admin
console shows a **Restart required** banner naming the variables that changed (never
their values) with the number of live sessions. Restart from the banner: the gateway
stops taking new sessions, waits for live ones to end (up to the minutes you choose, or
ends them at once), then exits 0. What starts it again:

- **systemd** (deb/rpm): the unit has `Restart=always`; the service is back within seconds.
- **Docker Compose**: `restart: unless-stopped` in the shipped compose file.
- **Kubernetes**: the pod's restart policy.
- **Anything else**: make sure your process manager restarts the service, or use
  `systemctl restart zanskar` by hand instead.

The check needs the running service to read the env file: `zanskar init` writes it
`root:zanskar 0640`. A file created by hand as `0600 root` shows "cannot check" in the
console; fix with `chgrp zanskar /etc/zanskar/env && chmod 0640 /etc/zanskar/env`. If the
file lives elsewhere, set `ZANSKAR_ENV_FILE=<path>` in it. Containers normally have no
file and the check is off.
- Cookies are `Secure`, `HttpOnly`, `SameSite=Strict` when TLS is on; do not set
  `ZANSKAR_TRUST_PROXY_TLS` in the in-pod TLS mode.
- Recordings volume: only the gateway identity can read it; the API records every view.
- Gateway pods run as non-root on a distroless image with a read-only root filesystem
  and all capabilities dropped; keep `readOnlyRootFilesystem` when adding sidecars.
- Ship the audit log to your SIEM: `ZANSKAR_SIEM_SYSLOG_ADDR` (syslog/CEF),
  `ZANSKAR_SIEM_WEBHOOK_URL` with `ZANSKAR_SIEM_WEBHOOK_SECRET` (signed JSON). These are
  being added alongside this chart and are described in the configuration reference;
  pass them through `config.extraEnv` / `config.extraEnvFrom`.
- Verify the audit chain on a schedule: `zanskar audit verify` from a CronJob.
- Keep guacd at 1.6 or newer (certificate pinning, ADR 0012); Dependabot tracks the
  compose image, and `guacd.image.tag` in the chart.
