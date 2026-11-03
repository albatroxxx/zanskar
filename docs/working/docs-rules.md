# Documentation rules

## Plain words

Write as you would explain it to a colleague at the next desk: short sentences, the thing named,
the reason given. No marketing, no "seamless", no "robust". The console says less; the docs say
what the console cannot: why, what happens next, what to do when it fails.

## Every snag a tester hit is documented

If somebody installing or using Zanskar tripped on something — cosign is not in the distro
repositories, the environment file must be edited after `init`, an LDAPS certificate must be
trusted first, a WinRM account must be a local administrator — the guide says it at the step where
it bites, in the tester's words. The guide is a record of what was hard, not of what was easy.

## Screenshots match the UI

A screenshot in the guide or on the site shows the release it documents: when the UI changes, the
screenshot is retaken (from a Linux gateway, at the release's build) before the release goes out. A
picture of an old sidebar or a removed tile is a documentation bug.

## The history is honest

Release notes are kept for every version, release candidates included, and say what each carried
and what it got wrong ("1.18.0 was published on the 3rd; the site said the 4th"). A superseded
version stays in the list, marked so. Dates are the real ones. Nothing is reworded after the fact
except to correct a fact.

## A release note's shape

The posture change first, in bold, when there is one. Then **Added**, **Changed**, **Removed**, in
sentences that say why, with the ADR named. Then **Upgrading from X**: what to back up, which
migrations run, what to check after. The first line of the note is what the site's release page
and the update check show.

## The site and the API document are kept in step

`site/` is the public site (the guide, the releases page, `latest.json` for the update check);
`python3 -I hack/check-site.py` runs before anything there is committed. `docs/api/openapi.yaml`
describes every route and is parsed by a test; a new field, path or enum value goes in with the
code, not after. The Terraform provider's README lists what the provider can set and must agree
with the server.

## ADRs are documentation

A reader who wants to know why something is the way it is reads the ADR, not the commit log. Keep
the ADR index complete and the status lines current; amend, do not rewrite
([decisions.md](decisions.md)).
