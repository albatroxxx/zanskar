# Deploying Zanskar

Zanskar is one static binary (the web UI is embedded), a database and, for RDP and VNC,
a guacd sidecar. The database is SQLite, built in, by default; PostgreSQL is an option.
Zanskar runs as a single instance; high availability is planned. This guide covers a
package install, a single node with Docker Compose, and Kubernetes with the Helm chart in
`deploy/helm/zanskar`.

## Topology

```
 browsers ──TLS──▶ load balancer / ingress ──TLS──▶ zanskar gateway (one pod)
                                                   │        │        │
                                                   │        │        └──▶ targets: SSH 22, WinRM 5986
                                                   │        └──▶ guacd (ClusterIP, isolated) ──▶ targets: RDP 3389, VNC 5900
                                                   └──▶ SQLite or PostgreSQL   recordings: volume or S3
                                                        cloud APIs (autoscaling groups, via the pod identity)
```

- **The gateway** keeps two structures in memory, described under
  [One gateway instance](#one-gateway-instance). Everything durable is in the database and
  the recordings store.
- **guacd** must only be reachable from the gateway. It speaks an unauthenticated
  protocol and carries target credentials in flight (threat model, ADR 0002).
- **Recordings** are append-only files. Use a persistent volume, or object storage (an
  S3-compatible bucket, set at install or from the console's Settings page; see Recording
  storage below).

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

**RDP, VNC and applications need guacd, which the package does not install.** Start the official
container on loopback only (guacd is unauthenticated; never publish it wider), then set
`ZANSKAR_GUACD_ADDR=127.0.0.1:4822` (or pass `-guacd` to `init`) and restart, or set the
guacd address on the console's Settings page, which applies without a restart (the console
accepts a loopback or private address only, and asks for a fresh authenticator code):

```sh
sudo docker run -d --name guacd --restart unless-stopped -p 127.0.0.1:4822:4822 \
  -e HOME=/tmp --read-only --tmpfs /tmp:size=512m,mode=1777 \
  guacamole/guacd:1.6.0@sha256:8974eaa9ba32f713daf311e7cc8cd7e4cdfba1edea39eed75524e78ef4b08f4f
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
(ADR 0014): it asks for the listen address and TLS mode (a managed certificate, the
default; your own certificate files; or behind a TLS proxy on loopback), the data
directory, whether to enable RDP and VNC, MFA and logging; it generates the master key and prints the migrate and admin-create steps. It
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

The file needs Docker Compose 2.20 or newer (the health checks below say why); check with
`docker compose version`. Docker's own repository ships a current `docker-compose-plugin`, and
the `docker-compose-v2` package on Ubuntu 22.04 and 24.04 and Debian 13's package are new
enough. Debian 12's own `docker-compose` package is the old Compose v1, with no
`docker compose` command at all: on Debian 12, install Docker from Docker's repository.

The stack pulls the published image `ghcr.io/albatroxxx/zanskar:${ZANSKAR_VERSION:-latest}`
(linux/amd64 and linux/arm64, signed with Sigstore — verification commands are in each
release's notes; `cosign` is not in the Ubuntu, Debian or RHEL repositories, so install it from
[its own release](https://github.com/sigstore/cosign/releases/latest) first). `latest` only ever points at a stable release; to run a release candidate
set `ZANSKAR_VERSION` explicitly in `deploy/.env`.

```sh
cp deploy/.env.example deploy/.env    # then set ZANSKAR_MASTER_KEY (openssl rand -base64 32)
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml exec \
  zanskar /zanskar admin create --username admin --name "Your Name"
```

`admin create` asks for the password twice without echo (`exec` gives it a terminal). Do not
put the password on the command line, where it lands in your shell history. A script can read
it without echo and pass it through:
`read -rs ZANSKAR_ADMIN_PASSWORD && export ZANSKAR_ADMIN_PASSWORD`, then
`docker compose -f deploy/docker-compose.yml exec -e ZANSKAR_ADMIN_PASSWORD zanskar /zanskar admin create ...`.
`-e` with a name and no value passes the variable from your shell, so history holds only its
name, not the password.

To build the image from a checkout instead (contributors, unreleased changes), add the
override file: `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.build.yml up -d --build`.

Every long-running service has a health check, and `docker compose -f deploy/docker-compose.yml ps`
shows it: Caddy's admin API answering on its own loopback, guacd's port 4822 open, and the
gateway's `/readyz`, which the gateway's image asks itself with `zanskar healthcheck` because
it has no shell, curl or wget. Caddy starts only once the gateway is healthy, so the first
requests are not refused with 502. `zanskar healthcheck` arrived after 1.3.0: with 1.3.0 or an
older image the gateway never turns healthy, and Compose starts Caddy anyway within a minute,
with a warning, rather than leaving the site down. That fallback (`required: false` on Caddy's
dependency) needs Docker Compose 2.20 or newer; an older Compose refuses the file.

Caddy, guacd and the gateway run with a read-only root filesystem and every Linux capability
dropped, except the one Caddy needs to bind ports 80 and 443; Caddy keeps its certificates and
saved configuration in the `caddy_data` and `caddy_config` volumes. Caddy and guacd are pinned
by the digest of their multi-arch image, so a tag pushed again upstream cannot change what runs;
Dependabot proposes the next digest. To pin the gateway image as well, give `ZANSKAR_VERSION`
its digest after the tag, as in `ZANSKAR_VERSION=1.3.0@sha256:<digest>`; `docker buildx
imagetools inspect ghcr.io/albatroxxx/zanskar:<tag>` prints it.

By default Caddy serves `https://localhost/` with a self-signed certificate from its
internal CA (a browser warning, fine for a trial). For a real certificate, set
`ZANSKAR_SITE_ADDRESS` to a public hostname in `deploy/.env` and make ports 80 and 443
reachable with DNS pointing at the host; Caddy fetches one from Let's Encrypt
automatically. The gateway trusts Caddy's `X-Forwarded-*` headers — so the audit log
records real client IPs — via `ZANSKAR_TRUST_PROXY_TLS` and the pinned `172.28.0.0/16`
network in `ZANSKAR_TRUSTED_PROXIES`; if that subnet collides with an existing network,
change it in both places in the compose file. For single sign-on (OIDC) behind the proxy, also
set `ZANSKAR_PUBLIC_URL` to the address people use (`https://<your host>`): the gateway sees
plain HTTP from the proxy and cannot build the https redirect URI the provider has registered.

The SQLite database and local recordings live in the `zanskar_data` volume; back them up
with `zanskar backup` (see [Backups and key custody](#backups-and-key-custody)) or by
snapshotting the volume. To exercise the PostgreSQL path instead, use
`deploy/docker-compose.dev.yml` — a plaintext-on-loopback development stack, not for
production.

## Kubernetes with the Helm chart

> **Preview.** The chart installs and runs one gateway pod. Zanskar runs as a single
> instance; high availability is planned (see [One gateway instance](#one-gateway-instance)).
> Keep `replicaCount: 1`, the default, and treat the chart as an evaluation path.
> `image.tag` defaults to the chart's `appVersion`, which tracks the current release tag.

Prerequisites: a PostgreSQL 14+ database, a `kubernetes.io/tls` certificate for the
pod (cert-manager is the easy path), an ingress controller that supports WebSockets,
and, for recordings, a persistent volume or an S3 bucket.

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

5. **Autoscaling groups on EKS (IRSA).** Give the gateway pod an IAM role by annotating
   the service account (`serviceAccount.annotations: eks.amazonaws.com/role-arn: ...`).
   That role is the principal that assumes each group's cross-account role with the
   ExternalId Zanskar generated; set `config.awsGatewayPrincipal` to the same ARN so the
   trust policy shown to admins is correct. The per-group role needs only the
   permissions the admin UI renders (Describe calls, console output, Instance Connect).

6. **Ingress.** Terminal sessions are long WebSockets; the default values carry
   ingress-nginx annotations with one-hour proxy timeouts. They also set cookie affinity
   (`session-cookie-name: zanskar_pod`) and the Service sets `sessionAffinity: ClientIP`.
   With one pod these change nothing; they are there so a connect ticket and the
   WebSocket that redeems it reach the same pod.

## One gateway instance

Zanskar runs as a single instance; high availability is planned. Run one gateway: one
package install, one Compose stack, or one pod (`replicaCount: 1`, the chart's default).
Two pieces of state live only in the gateway's memory:

| State | Location |
|---|---|
| Users, policies, targets, credentials (sealed), audit chain, sessions | the database |
| Recordings | the recordings volume or S3 |
| Connect tickets (30 s, single use) | gateway memory |
| Live-session registry (what is connected right now) | gateway memory |

Why a second replica is not supported:

- **Admin "terminate" and auditor "shadow" act only on the gateway that receives the
  request.** With two pods, a terminate that lands on the wrong pod ends the session in
  the database but leaves the live connection running, and shadow answers "not live here".
  Ending live sessions when access is taken away (a policy, group or account change) has
  the same limit. A control channel between pods fixes this; it is on the [roadmap](roadmap.md).
- **A connect ticket can only be redeemed on the pod that issued it**, so every pod would
  need sticky sessions.
- **The autoscaling sync loop would run on every pod**, duplicating cloud API calls.

## Upgrades and migrations

Migrations are explicit and forward-only. The chart's hook Job applies them before the
new pod starts; the packaged systemd unit runs `zanskar migrate` before every start, and the
compose stack's `zanskar-migrate` service before the gateway, so a restart is enough there.
Run `zanskar migrate` yourself only where you start `serve` some other way. Take a database
backup first. On an upgrade the chart stops the old pod before it starts the new one
(`strategy: Recreate`), so two gateways never run at once; `terminationGracePeriodSeconds`
gives live sessions a minute to close.

Upgrading to 1.7 from 1.5 or 1.6: migration 0032 drops the apps domain setting, the
applications certificate and the per-application label, since applications now open in an
isolated browser (ADR 0034) instead of under an apps domain. Applications enrolled under
1.5 or 1.6 keep their upstream and work through the browser once the gateway host has guacd
and a container runtime (see [Applications](#applications)).

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
archive**, only a fingerprint of it, so restore can warn on a mismatch. Only regular files
are copied: a symbolic link in the recordings directory is skipped (and counted in a warning),
since the gateway writes none there and backup usually runs as root.

Restore into a stopped service, then start it:

```
systemctl stop zanskar
zanskar restore --in /secure/zanskar-2026-09-22.tar.gz --force
systemctl start zanskar
```

Run as root, restore gives the database and recordings it writes to the owner of the files they
replace (or of the directory they land in), so the service's own user can open them. A symbolic
link already sitting where a restored file or directory goes is removed first, never written
through.

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
- **A key file instead** (ADR 0025): to keep the key out of `/etc/zanskar/env`, move it to
  a file of its own and point `ZANSKAR_MASTER_KEY_FILE` at it. The file must be readable by
  its owner only, or the gateway refuses to start:

  ```sh
  sudo install -m 0400 -o zanskar -g zanskar /dev/null /etc/zanskar/master.key
  sudo sh -c 'grep "^ZANSKAR_MASTER_KEY=" /etc/zanskar/env | cut -d= -f2- > /etc/zanskar/master.key'
  sudo sed -i 's|^ZANSKAR_MASTER_KEY=.*|ZANSKAR_MASTER_KEY_FILE=/etc/zanskar/master.key|' /etc/zanskar/env
  sudo systemctl restart zanskar
  ```

  `zanskar key rotate-master` then rewrites that file, keeping its owner and mode. The new
  key always goes where the service reads the old one: with the key in the environment, pass
  `-env-file /etc/zanskar/env`; with a key file, name no file at all (or that one). Any other
  file is refused, since the service would start with a key that no longer opens anything.
  With `-generate`, the new key is staged in `<file>.next` (mode 0600) before the database is
  rewrapped and removed once the file carries it, so a crash in between leaves the key on disk
  rather than nowhere; with no file to update, the key is printed first instead. An env file
  line written as `export ZANSKAR_MASTER_KEY=...` or with quotes is read and rewritten as such,
  by `rotate-master` and by `init --force` alike.

## Security checklist

- TLS on the pod (`tls.secretName`) and on the ingress; HSTS is sent automatically when
  the gateway serves TLS.
- guacd isolated by the NetworkPolicy the chart installs; never expose port 4822.
- `ZANSKAR_REQUIRE_MFA=true` (default). Do not turn it off outside throwaway installs.
  The console's Settings page can override it; the change is audited and shows its source.
- The session cookie is `Secure`, `HttpOnly`, `SameSite=Strict` when TLS is on; do not set
  `ZANSKAR_TRUST_PROXY_TLS` in the in-pod TLS mode.
- Recordings volume: only the gateway identity can read it; the API records every view.
- The gateway pod runs as non-root on a distroless image with a read-only root filesystem
  and all capabilities dropped; keep `readOnlyRootFilesystem` when adding sidecars.
- Ship the audit log to your SIEM. `ZANSKAR_SIEM_SYSLOG_ADDR` (`tcp://` or `tls://`) sends
  syslog in CEF, or JSON with `ZANSKAR_SIEM_SYSLOG_FORMAT=json`; `ZANSKAR_SIEM_SYSLOG_CA`
  names a CA file for a private authority. `ZANSKAR_SIEM_WEBHOOK_URL` (https) with
  `ZANSKAR_SIEM_WEBHOOK_SECRET` (16 characters or more) posts signed JSON batches. Both
  can be set together. In the chart, pass them through `config.extraEnv` /
  `config.extraEnvFrom`. The webhook signature a receiver checks is described under
  [SIEM export](#siem-export).
- Ship the gateway's own log off the host too: its `audit anchor` lines are the copy of
  the audit log's anchors that lives outside the database ([Audit anchors](#audit-anchors)).
- Verify the audit log on a schedule: `zanskar audit verify` from a CronJob or a timer,
  with `--anchor` and a line kept outside the database.
- Keep guacd at 1.6 or newer (certificate pinning, ADR 0012). Its image is pinned by tag
  and digest in the compose files, the chart's `guacd.image`, the command `zanskar init`
  prints, this guide and the AWS user data. A test fails when one of them names a different
  image from the compose file, so an upgrade changes them together:
  `hack/bump-guacd.py guacamole/guacd:<tag>@sha256:<digest>` moves every copy at once, and
  finishes a Dependabot pull request that bumped the compose files alone.

## The audit log outside the database

Every audit event is hashed onto the one before it (ADR 0008), so editing or removing an
event breaks the chain from there on. Deleting the *newest* events leaves a chain that still
links; the anchors and the id-sequence check below are what notice that.

### SIEM export

`ZANSKAR_SIEM_SYSLOG_ADDR` sends one RFC 5424 message per event over `tcp://` or `tls://`,
with octet-counting framing: a CEF record (the event id as `externalId`, its hash as `cs3`),
or the event as JSON with `ZANSKAR_SIEM_SYSLOG_FORMAT=json`. UDP is not offered, since audit
delivery must not be silently lossy.

`ZANSKAR_SIEM_WEBHOOK_URL` receives `POST` requests whose body is `{"events":[...]}`, each
event with its `id`, `hash` and `prev_hash`. Each request is signed with
`ZANSKAR_SIEM_WEBHOOK_SECRET`:

```
Content-Type: application/json
X-Zanskar-Timestamp: <unix seconds>
X-Zanskar-Signature: sha256=<hex of HMAC-SHA256(secret, timestamp + "." + body)>
```

A receiver computes the HMAC over the `X-Zanskar-Timestamp` value, a literal `.`, and the
request body exactly as received, before any JSON parsing; compares it with the header in
constant time; and refuses a timestamp more than a few minutes from its own clock, so a
captured request cannot be replayed later. Delivery is at least once: a batch the receiver
does not answer with a 2xx is sent again, so treat the event `id` (or `hash`) as the
idempotency key. Each sink keeps its own position across restarts. Redirects are not
followed: a 3xx answer counts as a failed delivery, so give the receiver's final address.

### Audit anchors

The gateway signs the head of the audit log, the newest event's id and hash, when it starts
and every hour after (when there is a newer event), with HMAC-SHA256 under a key derived from
the master key. Each anchor is stored in the database and logged once as `audit anchor`:

```
{"time":"…","level":"INFO","msg":"audit anchor","anchor_id":12,"event_id":5310,"hash":"4be1…","created_at":"2026-10-11T09:00:00.123456Z","mac":"9f0c…"}
```

That log line is the copy outside the database, as long as the gateway's log (the journal,
or your cluster's log pipeline) is shipped somewhere the database's administrators cannot
edit. `zanskar audit anchor` writes one on demand and prints it as a line to keep:

```
$ zanskar audit anchor
anchor 5310 4be1… 2026-10-11T09:00:00.123456Z 9f0c…
```

`zanskar audit verify` checks each stored anchor's signature and that the event it names is
still in the log with the hash it signed, and compares the id sequence with the newest event.
`--anchor "<line>"`, which may be repeated, checks a line kept outside the database the same
way. It exits 0 when everything checks out, 1 when something does not and 2 on a malformed
command line; the console's audit page shows the same result.

- **Stored anchors** notice the newest events being deleted, and any rewrite of an anchored
  event, by someone who can write to the database but leaves `audit_anchors` alone. Without
  the master key an anchor can be deleted but not forged or altered; a row that does not
  verify is reported as not written by this gateway.
- **The id sequence** notices the newest events being deleted before an anchor covers them.
  On SQLite that is a failure. On PostgreSQL a failed insert also uses up an id, so it is a
  warning to look into.
- **A line kept outside the database** is what notices someone with full database access,
  who can also delete the stored anchors and rewind the sequence. On a package install whose
  journal is shipped off the host, a scheduled check against the newest logged anchor:

  ```sh
  line=$(journalctl -u zanskar -o cat -g '"msg":"audit anchor"' | tail -n 1 |
         jq -r '"\(.event_id) \(.hash) \(.created_at) \(.mac)"')
  sudo bash -c "set -a; . /etc/zanskar/env; set +a; \
    runuser -u zanskar -- zanskar audit verify --anchor '$line'"
  ```

  Checked on the gateway against its own journal, this proves little; check against the
  copy your log pipeline keeps.

`zanskar key rotate-master` re-signs the stored anchors under the new key. Lines kept from
before a rotation were signed with the old key and no longer verify, so restart the service
right after rotating, run `zanskar audit anchor` and keep the new line. Until the restart the
running gateway still holds the old key; rather than write an anchor nothing could verify
later, it writes none and logs `audit anchor failed` saying so. The same refusal, and the
same log line, follows an anchor that is not this gateway's, such as one restored from
another install's backup or edited in place: `zanskar audit verify` names it as not written
by this gateway; remove that row and anchoring resumes. `zanskar audit reseal` removes the stored anchors over the events it
rewrites and anchors the new head; lines kept for the rewritten events then fail, which is
the record that the log was rewritten.

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

### A certificate from Let's Encrypt

In `managed` (or `file`) mode the gateway can get its certificate from an ACME CA itself,
Let's Encrypt by default, instead of running Caddy or another proxy only to hold one (ADR
0021, amended 2026-10-30). Three runtime settings under Settings › Let's Encrypt turn it on:
`tls.acme` (*Certificate from Let's Encrypt*, off by default), `tls.acme_email` (the account
email the CA writes to about the certificate) and `tls.acme_directory` (the ACME directory,
`https://acme-v02.api.letsencrypt.org/directory` by default; Let's Encrypt's staging
directory or a private ACME CA, `https://` only).

- **What it orders.** The host of `ZANSKAR_PUBLIC_URL` and the DNS names among
  `ZANSKAR_TLS_HOSTS`, and nothing else: IP addresses, bare words and `localhost` are left
  out, and a TLS handshake naming anything else never starts an order, so a stranger's SNI
  cannot make the gateway ask the CA for a certificate. The names are read at start; a
  change to either variable takes effect with the restart it needs anyway.
- **The challenge.** The CA must reach the gateway from the internet on that name. TLS-ALPN-01
  is answered on the TLS listener (443 in the default install) and HTTP-01 on the
  `ZANSKAR_HTTP_REDIRECT_ADDR` listener (80), before its redirect. A gateway reachable only
  on a private network cannot use Let's Encrypt; upload a certificate from your own CA.
- **Which certificate is served.** An uploaded certificate first, for every name; then ACME's,
  for the names it covers, while it is on; then the file (`file` mode); then the self-signed
  one. Turning ACME off goes back to the next in that order at once.
- **Orders and failures.** An order runs in the background. A handshake waits for it at most
  10 seconds and is then served the next certificate in the order above, so a CA outage never
  holds connections; one order per name runs at a time, and a name whose order failed is not
  tried again for 10 minutes. Certificates are renewed 30 days before they expire.
- **Where it is kept.** The ACME account key and the certificates are sealed with the master
  key in the `acme_cache` table (migration 0038, on SQLite and PostgreSQL), so a second
  gateway on the same database serves the same certificate instead of ordering its own;
  `zanskar key status` counts its rows by key version like every other sealed table.
- **What the console shows.** The TLS certificate card says what Let's Encrypt serves and
  until when, or why it could not get one. In `proxy` mode the card says the proxy holds the
  certificate and how to switch the mode (see the next section).

Moving from Caddy to the gateway's own certificate on a package install: set the public URL
to the name Caddy served, turn Let's Encrypt on, stop and disable Caddy
(`sudo systemctl disable --now caddy`), then switch the TLS mode to *managed* under Settings
› Set at install. Caddy must be stopped first: the gateway takes 443 and 80, and if it cannot
bind them the change is rolled back after about a minute.

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

Keep the bucket private, with public access blocked and a bucket policy that admits the
gateway's role or key alone. The gateway writes every object with server-side encryption,
under the KMS key you name or else the bucket's own AES-256, and does not encrypt recordings
itself before upload; so the bucket policy and the key policy are what keeps a recording from
anyone who can reach the bucket. Local recordings are `0600` files in a `0700` directory owned
by the service, and `zanskar backup` copies them into the archive as they are: store the
archive encrypted.

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

  Or without an editor, as root:

  ```
  mkdir -p /etc/systemd/system/zanskar.service.d
  printf '[Service]\nSupplementaryGroups=docker\n' > /etc/systemd/system/zanskar.service.d/docker.conf
  systemctl daemon-reload && systemctl restart zanskar
  ```

  Check with `sudo -u zanskar -g docker docker info`. This is a decision for the host's root:
  the Docker socket is root-equivalent, so neither the console nor the `zanskar` command can
  grant the service that group. For Podman, point `ZANSKAR_DOCKER_PATH` at the `podman`
  binary.
- **What the container CLI is given:** it starts with `PATH`, `HOME` and the variables that
  say which daemon to reach and how (`DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CONFIG`,
  `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY`, `DOCKER_TLS`, `DOCKER_API_VERSION`, and for Podman
  `XDG_RUNTIME_DIR`, `CONTAINER_HOST`, `CONTAINER_CONNECTION`, `CONTAINERS_CONF`), plus the
  session's own sidecar settings; nothing else from the gateway's environment. Set those in the
  environment file if the daemon is not the local default. The gateway also removes the master
  key, the database DSN, the webhook secret, `ZANSKAR_ADMIN_PASSWORD` and
  `ZANSKAR_NEW_MASTER_KEY` from its own environment once it has read them at start, so no
  process it starts inherits them. The kernel's copy of the environment the service started
  with (`/proc/<pid>/environ`) is not changed, and stays readable by the service user and
  root; keep the master key in `ZANSKAR_MASTER_KEY_FILE` to keep it out of that copy too.
- **Containment on the host:** the session network is internal, so the client container
  reaches its proxy and nothing else; only the proxy is also on the runtime's default
  bridge, through which it reaches the database. Docker 28.1 or newer also keeps the
  gateway host's own address off that network (an older daemon leaves it reachable from
  the client container, and the gateway logs a warning per session). Every container and
  network is labelled `zanskar.managed=1` and `zanskar.session=<id>`; at start and every
  five minutes the gateway removes those that belong to no session it runs and are older
  than two minutes, so a crash leaves nothing behind. `ZANSKAR_DATABASE_MAX_SESSIONS`
  (default 20, `0` for no cap) bounds how many database sessions run at once; a user past
  it is told the gateway is full and to retry.
- **Images pulled on first use:** `postgres:<version>-alpine` and `edoburu/pgbouncer` for
  PostgreSQL; `mysql:<version>` or `mariadb:<version>` and `ghcr.io/albatroxxx/zanskar:<your
  version>` for MySQL and MariaDB. The first session that needs one pulls it before its
  set-up starts, under a deadline of its own (ten minutes), so that session takes as long as
  the pull. Pull them ahead of time to spare the first user, and on an air-gapped host; the relay
  image can be pointed at a mirror with `ZANSKAR_DBPROXY_IMAGE` or the console's Settings
  page. It must be an image reference: `registry/repository`, an optional `:tag` and an
  optional `@sha256:<64 hex digits>` to pin it by digest. The console refuses anything else,
  and an environment value that is not one is ignored in favour of the default. The default
  is the gateway's own image by version tag, not by digest: the digest of an image is known
  only once it is built, and the binary inside it, which names the default, is built first.
- **TLS to the database** is verified by default (ADR 0025): a new database target uses
  `verify-full` and needs the CA bundle that signs the database's certificate. For Amazon
  RDS that is your region's bundle,
  `https://truststore.pki.rds.amazonaws.com/<region>/<region>-bundle.pem` (the global
  bundle is too large). `require` and `prefer` encrypt without verifying and are marked as
  such in the console. Targets created before 1.2.1 keep the `prefer` they had.
- Not available inside the Compose stack; use the package install for database targets.

## Applications

Web applications are opened in a browser that runs beside the gateway, in a container made
for that session, and streamed to the user as pixels through guacd, the way a VNC desktop is
(ADR 0034). An application is a target with an upstream (`http://host[:port]` or
`https://...`), granted by policies under the protocol `http`. No apps domain, no
certificate, no DNS record, nothing installed on the client.

- **The gateway host needs guacd and a container runtime.** The guacd address is the one
  RDP and VNC use (`ZANSKAR_GUACD_ADDR` or the Settings page). The runtime is Docker or
  Podman reachable by the `zanskar` service user: the same `SupplementaryGroups=docker`
  drop-in as [database access](#database-access), or `ZANSKAR_DOCKER_PATH=podman`. guacd
  must be on the runtime's default bridge, which is where the `docker run` above puts it (no
  `--network` flag); the AWS reference install connects its guacd to the bridge by hand.
  Until these are in place the Applications page shows a checklist (guacd, container
  runtime, browser image) and a connect answers 501 `protocol_unavailable`.
- **Enrolment.** Applications, *Add*: a name, the upstream, an optional CA bundle for an
  https upstream, and tags; then a policy granting `http` on it. An https upstream is
  verified by the browser against the system roots or against the bundle, never switched
  off. The upstream's address follows the same rules as any target: no loopback, link-local,
  cloud metadata service or the gateway's own listener.
- **What a session starts.** An internal network with no route out. A browser container,
  `ghcr.io/albatroxxx/zanskar-browser` (Debian's Chromium and TigerVNC), on that network
  alone: kiosk mode, an unprivileged user, Chromium's own sandbox on, a read-only filesystem,
  no capabilities, `no-new-privileges`, pid and memory limits, and a seccomp profile that is
  Docker's default plus the namespace and chroot calls the sandbox needs. A relay container,
  the gateway's own image running `zanskar apprelay`, on that network and on the default
  bridge: it forwards the upstream's port, and only that port, to the resolved upstream
  address, and exposes the browser's VNC port on the bridge side, where guacd connects to it
  with a password made for the session; it accepts exactly one VNC connection. The browser's
  resolver maps the upstream's host name to the relay and everything else to nothing.
  Chromium policy allows the upstream's origin only and blocks downloads, printing,
  developer tools, extensions, sign-in, sync, password saving, autofill, safe browsing and
  metrics. Everything is destroyed when the session ends; a reaper removes what a crash
  leaves behind.
- **Sessions** are desktop sessions with protocol `http`: on the Sessions pages, terminable
  there, shadowable, recorded as a pixel stream and replayable, with the policy's idle and
  maximum limits and its clipboard rule. The audit chain records `session.connect`,
  `session.start` and `session.end`, as for a desktop. An application holds no credential:
  the application's own sign-in, if it has one, is the user's.
- **The first session pulls the images.** A host that has never run an application pulls
  the relay (the gateway's own image, about 45 MB) and the browser image (about a 270 MB
  download, 660 MB on disk) before the first session starts, under a deadline of its own, and the
  console shows *Connecting* until the first frame; on a slow link that first session takes
  minutes. The Applications checklist says when the browser image is not on the host yet. To
  spare the first user, pull ahead on the gateway host:

  ```
  docker pull ghcr.io/albatroxxx/zanskar-browser:<version>
  docker pull ghcr.io/albatroxxx/zanskar:<version>
  ```
- **Upgrades and disk.** Both images follow the gateway's version, so every upgrade pulls
  new ones. From 1.9.0 the gateway removes the earlier versions' images itself: on start and
  every five minutes after, it removes from the browser and relay images' repositories every
  image that carries Zanskar's source label (`org.opencontainers.image.source`) and is not
  the configured one, records `system.images_remove` with the references it removed, and
  logs them. It never forces a removal, so an image a container still uses (a Compose
  gateway's own, a running session's relay) stays, and an image without the label, such as
  a custom build pushed to the same repository, is never a candidate. It removes the old
  images before the first session pulls the new ones, which is the order a nearly full disk
  needs. **Remove old images** (`updates.remove_old_images`, under *Updates* on the Settings
  page) turns it off, to keep an earlier version's images for a rollback on a host with no
  registry access; two gateways on one Docker host should turn it off too, or each removes the
  other's images between sessions, and so does a released binary started for a test on a
  host whose images you want to keep. A development build removes nothing. An upgrade also downloads less than the image's size: the
  release builds the browser image's package layer only when Debian's packages changed since
  the last release, and takes it from that release's image otherwise, so between two releases
  with the same Chromium only the small layers after it are new.
- **Settings.** `apps.browser_image` (`ZANSKAR_BROWSER_IMAGE` in the environment file)
  names the browser image; the default is the published image at the gateway's version.
  From the console it takes a digest-pinned reference only, behind a fresh authenticator
  code, under the same rules as the relay image. `database.proxy_image`, titled *Relay
  image* on the Settings page, is the gateway's own image and serves both the MySQL relay and
  the application relay. `ZANSKAR_APPS_MAX_SESSIONS` (default 10) caps open application
  sessions; a user past it is answered 503 `too_many_sessions` and told to retry.
- **Cost.** Each open application is a Chromium: about half a gigabyte of memory and a core
  under load. The cap bounds it.
- **Not in this version:** resizing after the session opens (the screen is the size the
  user's window had when they opened it), sound, file upload into the application, and
  credential autofill from the vault.
- Not available inside the Compose stack or on Kubernetes, where the gateway container has
  no container runtime; use the package install, as for database targets.

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

`zanskar config check --env /etc/zanskar/env` says whether the gateway would start with a
file, without opening the database or touching the running service: it reads the file as
systemd does and loads it as `serve` would, printing `ok: the gateway would start with …`
or the error `serve` would stop on. Run it after editing the file by hand and before the
restart.

### Changing them from the console

On a package install some install-time settings can be changed from Settings › Set at
install, without a shell (ADR 0020, amended 2026-10-30). The gateway never writes its own
environment file: it asks, and a helper running as root on the host decides and writes.

- **What can be changed.** `ZANSKAR_PUBLIC_URL` (an `https://` address with no path),
  `ZANSKAR_TLS_HOSTS` (host names or IP addresses, comma separated, at most 32),
  `ZANSKAR_ISSUER` (at most 64 printable characters; authenticators enrolled before keep the
  old name), `ZANSKAR_LOG_FORMAT` (`json` or `text`), `ZANSKAR_APPS_MAX_SESSIONS` and
  `ZANSKAR_DATABASE_MAX_SESSIONS` (0 to 1000) and `ZANSKAR_AWS_GATEWAY_PRINCIPAL` (an IAM
  role or user ARN). An empty value takes the line out. The **TLS mode** changes only as a
  preset, so the mode, the listen address and the proxy trust move together and the gateway
  never comes up unreachable: *managed* sets `ZANSKAR_TLS_MODE=managed`,
  `ZANSKAR_LISTEN_ADDR=:443`, `ZANSKAR_HTTP_REDIRECT_ADDR=:80` and
  `ZANSKAR_TRUST_PROXY_TLS=false`; *proxy* sets `ZANSKAR_TLS_MODE=proxy`,
  `ZANSKAR_LISTEN_ADDR=127.0.0.1:8443`, `ZANSKAR_TRUST_PROXY_TLS=true` and takes the redirect
  out.
- **What stays install-only, and why.** The database (its credentials, and a different
  database is a different gateway), the master key (`zanskar key rotate-master` changes
  it), the container runtime path (any program path would run as the service user), the
  listen address outside the presets (the console could lock itself out), plain HTTP, the
  trusted proxies and the proxy trust outside the presets (they decide which client
  addresses and cookies are believed), the recordings directory and storage, and the SIEM
  export. The console marks these *Install only*, with the reason on hover.
- **The request.** `POST /api/v1/admin/settings/boot` takes `values` and/or `tls_mode` and
  `wait_minutes`. It needs an authenticator code proved within five minutes (403
  `step_up_required`), refuses at once what the helper would refuse (400 `invalid_change`,
  from the same checks), and is audited as `settings.boot_request` with the values (none of
  the allowlisted variables is a secret) before anything happens. The gateway then drains
  like a restart and writes `/var/lib/zanskar/config-request`.
- **The helper.** `zanskar-config.path` sees the file and starts `zanskar-config.service`,
  which runs `zanskar config apply --env /etc/zanskar/env --state /var/lib/zanskar` as root.
  It trusts nothing the gateway wrote: it removes the request first so a failure never
  loops, reads one JSON object of at most 16 KiB with no field it does not know, refuses the
  whole request on any variable outside the list above, a preset's variable given on its own,
  or a value with a quote, backslash, `$`, backtick or control character, and checks each
  value as above. It merges the change into the file, keeping every other line (comments,
  the master key, variables it does not know) byte for byte, and runs the result through
  `config check` before it replaces anything. It keeps the old file as
  `/etc/zanskar/env.previous`, with the same owner and mode, restarts the service, and waits
  up to 60 seconds for `/readyz` where the new file says the gateway listens.
- **Rollback.** If the gateway does not answer, the previous file goes back and the service
  restarts on it. The helper writes `/var/lib/zanskar/config-result`: `applied`, `refused` or
  `rolled_back`, with the names it changed and why, never a value. The console's progress
  view follows it (`GET /api/v1/admin/settings/boot/result`); a refusal ends the drain at
  once. The gateway audits the outcome once, as `settings.boot_apply` under the
  administrator who asked: the process that asked was restarted, so the next one records it
  at start.
- **Where it works.** The deb and rpm packages install `zanskar-config.path` and
  `zanskar-config.service` and enable the path unit on every install and upgrade. On a host
  without systemd (Docker, Kubernetes) the request is refused, 409 `unsupported_supervisor`,
  as the host actions are; change the environment where the container is defined. A gateway
  started from the release tarball, or by the AWS reference deployment's user data, has
  systemd but not the path unit: there the request waits, nothing changes, and after 10
  minutes the drain ends with *the helper did not answer within 10m0s; is
  zanskar-config.path enabled?*. To add it by hand, copy the two units from
  `deploy/packaging/` in the source (or from the package) to `/etc/systemd/system/`, change
  the service's `ExecStart=` if the binary is not `/usr/bin/zanskar` (the AWS reference
  install puts it in `/usr/local/bin`), then
  `sudo systemctl daemon-reload && sudo systemctl enable --now zanskar-config.path`. The path
  unit watches `/var/lib/zanskar`; a gateway with another `ZANSKAR_STATE_DIR` needs the
  unit's `PathExists=` and the service's `--state` changed to match.

## Reboot, stop and update from the console

The admin console's gear offers **Reboot host** and **Stop host** beside the restart; the
bell offers **Update now** when a newer release is published (ADR 0032). The gateway keeps
`NoNewPrivileges`; none of this is a privilege it holds:

- Reboot and stop run `systemctl reboot` / `systemctl poweroff`, which logind and polkit
  allow the `zanskar` user through rules the package installs
  (`/etc/polkit-1/rules.d/50-zanskar.rules`, and a `.pkla` for the polkit 0.105 still on
  Ubuntu 22.04). Each action drains live sessions first, needs the hostname typed and an
  authenticator code proved within five minutes (`POST /auth/mfa/step-up`), and is audited
  as `system.reboot` / `system.poweroff` before anything happens. A refused `systemctl`
  cancels the drain, so the gateway keeps serving, and is audited as a failure.
- The install writes the wanted version to `/var/lib/zanskar/update-request` after the
  drain; `zanskar-update.path` (root, shipped in the package) starts
  `zanskar-update.service`, whose script `/usr/libexec/zanskar/zanskar-update` downloads the
  release itself, verifies the cosign bundle over `SHA256SUMS` against the release
  workflow's identity, checks the package against those sums, refuses downgrades, installs
  with dpkg or rpm and restarts the service. Progress goes to `update-status.json`, which the
  console's progress view reads. The gateway never downloads a binary. It watches that
  report while it drains: when the installer reports this request failed, or has not
  finished within 20 minutes, the gateway serves again and audits `system.update` as a
  failure with the reason, instead of refusing new sessions until someone cancels by hand.
- Every action shows its progress in the console until it ends: waiting for live sessions,
  installing, restarting or rebooting, and back. Success is judged by the gateway's own
  answers (`GET /api/v1/admin/system/status`): a fresh process on the version asked for after
  an update, a fresh process after a restart or reboot, a gateway that stays away after a
  stop. `cosign` is a package recommendation; the
  installer refuses to run without it.
- The daily version check reads `https://albatroxxx.github.io/zanskar/releases/latest.json`
  (`ZANSKAR_UPDATE_MANIFEST_URL` for a mirror; the runtime setting under Settings › Updates
  switches it off). `ZANSKAR_STATE_DIR` (default: the working directory, `/var/lib/zanskar`
  under the unit) is where the request and status files live.
- Docker and Kubernetes: the host actions are greyed out and the endpoints answer 409; the
  bell still reports a new release with the upgrade step for that deployment.

## The environment file check

The check needs the running service to read the env file: `zanskar init` writes it
`root:zanskar 0640`. A file created by hand as `0600 root` shows "cannot check" in the
console; fix with `chgrp zanskar /etc/zanskar/env && chmod 0640 /etc/zanskar/env`. If the
file lives elsewhere, set `ZANSKAR_ENV_FILE=<path>` in it. Containers normally have no
file and the check is off.
