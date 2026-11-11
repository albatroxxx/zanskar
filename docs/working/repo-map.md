# Where things live

```
cmd/zanskar/            the binary: serve, migrate, admin, keygen, key rotate, init, update,
                        config (the root helper that applies install settings), apprelay,
                        dbproxy; openapi_test.go parses docs/api/openapi.yaml
internal/
  auth, user, group     sign-in (password, second factor, step-up), people, groups, roles
  idp                   identity providers: OIDC, LDAP, SCIM; vendor checks live in hack/
  credential, keyring,  vaulted credentials, the sealing keyring, the SSH certificate authority
  sshca, crypto
  target, asg, cloud    hosts, databases, applications; autoscaling groups; the gateway's own
                        cloud identity
  policy, access        access policies and grants; just-in-time requests and approvals
  connect, ticket,      session start (tickets, preflight, the WebSocket handlers per protocol),
  session, recording,   the session store and activity, recordings (asciicast, guac), their
  recstorage            storage (local, S3) and retention
  gateway/              what carries a session: sshgw, winrmgw, guac (desktops through guacd),
                        dbgw + mysqlrelay (databases), browsergw + apprelay (applications:
                        the isolated browser, the relay with its SOCKS and inspecting proxy),
                        containers (the hardened spawn path)
  audit, notify         the hash-chained audit log; notification channels and the mail server
  settings, bootedit,   runtime settings; install-time settings applied by the root helper;
  lifecycle, update     restart and upgrade; the daily release check
  server, httpx,        the HTTP server, the SPA, TLS certificates; handler helpers; the
  tlscert, apitoken     API tokens for automation
  configio              the configuration as a YAML file (export and import)
  cli                   the restricted console command line
  overview              the dashboards' numbers
  ipspace, protocol,    address classes (private, metadata, reserved); the kinds and protocols;
  store, logring,       the database layer and migrations runner; the in-memory log ring; the
  version               version string
  states, states/catalog  a record's lifecycle declared once (ADR 0047); the catalog lists them for
                        the guard tests and hack/gen-lifecycles (docs/lifecycles.md)
migrations/sqlite,      the numbered pairs, identical names
migrations/postgres
web/                    the console (React, Vite, vitest, Playwright in web/e2e)
site/                   the public site: guide, releases, latest.json (the update check reads it)
docs/                   adr/ (every decision), releases/ (every version), api/openapi.yaml,
                        architecture, threat model, roadmap, deploy, lifecycles.md (generated),
                        working/ (this)
deploy/                 Dockerfiles, compose stacks, the Helm chart, the AWS Terraform, packaging,
                        the browser image
hack/                   smoke.sh, e2e.sh, fakessh, wsclient, keycloak/ and authentik/ runs,
                        check-site.py, check-readme-links.py, gen-notices.sh, screenshots
terraform-provider-zanskar/  the Terraform provider, its own Go module, acceptance tests
```

Kinds are derived, never stored: an engine makes a database, an upstream an application,
anything else a host (`internal/protocol/protocol.go`). The places a kind is derived and the
places a protocol list is copied are listed in [ADR 0045](../adr/0045-kubernetes-clusters-as-targets.md)'s
plan; change them together, with a guard test.
