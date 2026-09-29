# 0021. The gateway manages its own TLS certificate, self-signed until one is uploaded

Date: 2026-09-29

## Status

Accepted. Builds on 0014 (env file is boot configuration) and 0020 (runtime settings are
applied live from the database).

## Context

Zanskar refuses plain HTTP off loopback, so a fresh install had two ways to be reached:
put a TLS-terminating proxy in front (the documented default, `zanskar init -behind-proxy`
plus Caddy), or hand `init` a certificate and key (`ZANSKAR_TLS_CERT/KEY`). The manual QA
round found both wanting for the first hour of an install (R2, R3, R10): most operators have
no certificate yet, a proxy is a second thing to install and understand, and once a
certificate did exist, replacing it meant editing files and restarting, dropping every live
session.

A certificate is exactly the kind of thing ADR 0020 says the console should own: it changes
while the gateway runs, it is applied per connection, and nothing about it needs the process
to start over.

## Decision

`ZANSKAR_TLS_MODE` selects how the listener is protected and is boot configuration:

- `proxy`: plain HTTP on loopback behind a TLS-terminating proxy, as before.
- `file`: the certificate and key named in `ZANSKAR_TLS_CERT/KEY`, as before.
- `managed`: the gateway serves TLS with a certificate it manages in the database.

Unset, the mode is derived from the other variables, so every existing install keeps its
behaviour.

In `file` and `managed` modes the listener asks a certificate manager for its certificate
on every handshake. The manager resolves, in this order: a certificate **uploaded in the
console**, the **file** certificate from the environment, and a **self-signed** one the
gateway generates at first start (P-256, two years, names: the listen host, the machine's
host name, its non-loopback addresses, localhost) and regenerates when within thirty days
of its end. An upload replaces what is served on the next connection; removing it falls
back down the list. Private keys are sealed by the key ring like every other secret and are
never returned by the API, written to the audit log or logged. Uploads are validated (key
matches, leaf within its validity, server authentication allowed, unencrypted key) and every
change is audited with the certificate's subject, names, expiry and SHA-256.

`zanskar init -managed-tls` writes the mode; the console's Settings page shows what is
served, its fingerprint and expiry, and takes uploads.

## Consequences

- A fresh install in managed mode is reachable over HTTPS with nothing else installed.
  Browsers warn about the self-signed certificate; the SHA-256 fingerprint the gateway logs
  at start and shows in Settings is the first-visit trust step, and the threat model says
  so. A real certificate ends the warnings without a restart.
- Certificate rotation is a console action, not a maintenance window.
- In `file` mode a console upload takes precedence over the file, consistent with ADR
  0020's console-over-environment rule; the Settings card says which is serving.

## Amendment (2026-09-29): the install default, and the redirect listener

With the certificate manager in place the first hour of an install can be HTTPS with
nothing else installed, so that becomes the default `zanskar init` writes: managed TLS on
`0.0.0.0:443`, and `ZANSKAR_HTTP_REDIRECT_ADDR=:80`, a plain-HTTP listener whose only
handler answers with a permanent redirect to the same path on the HTTPS listener (the
client's Host, validated as a host name or IP and stripped of its port, else the listen
host; the TLS port added when it is not 443). `-behind-proxy` keeps the previous shape,
loopback 8443 behind a proxy, and the container images stay behind Caddy on 8443.

The packaged unit grants `CAP_NET_BIND_SERVICE` (ambient and bounding set) so the
unprivileged service can bind the two ports; `NoNewPrivileges` stays on, which systemd
allows for ambient capabilities. A refused bind on a port below 1024 names the drop-in.

HSTS is sent whenever the gateway serves TLS. Browsers ignore it on a connection with
certificate errors, so the self-signed default pins nothing; once a real certificate is
uploaded, the two-year `max-age` applies from the first clean visit.
