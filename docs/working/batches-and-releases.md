# Batches and releases

## Work lands in batches, not drips

Every change is built on a branch off `main`, committed **locally**, one commit per change (a
fix is its own commit with its own message; a feature is one or a few), and **not pushed** until
the owner says the batch ships. Then the batch goes up as **one pull request** whose body
summarises it, is reviewed and merged once, and becomes one release. The reasons: a push costs a
ten-minute CI run that somebody waits on; a stack of small pull requests was merged in the wrong
order once (2026-10-13); and a release's notes are easier to write for a batch than for a drip.

The branch is named for what follows the last release (`fix/after-1-18-0`). It holds anything the
owner asked for since: fixes, copy, docs, an ADR. Nothing goes to `main` outside a batch except a
correction to the release just made (a wrong date in `site/releases/latest.json` went up as #312
within the hour, as its own pull request, and was said so).

## One push per review round

When the owner reviews on a running build (the local mock or the live gateway) and sends findings,
all of them are fixed locally and pushed **once**. Never stack open pull requests.

## Commit messages

The first line says what changed, in the voice of the code's comments; the body says why, with the
date and the place the need was found ("live, 2026-11-03: …"). A commit that fixes a finding names
it. Stage files **by explicit path**: `git add -A` committed somebody's scratch file once.

## The pull request

The body: what the owner asked for and when; a **posture change said first** when the release
widens what a session can reach (see [security-rules.md](security-rules.md)); then Added, Changed,
Removed; then what was verified locally. The same text, tidied, is the release note.

CI must be green: build, tests on SQLite and Postgres, lint, gosec, govulncheck, the migration-name
parity check, CodeQL, the web tests, the e2e specs. A CodeQL alert is fixed or **dismissed with a
written reason** (at most 280 characters; the reason is the record), never ignored; a SonarCloud
smell that is deliberate gets a `// NOSONAR` with the why beside it. Merge by **squash** with the
pull request's title as the subject; `--admin` bypasses the review count, never the checks.

## Release

1. Before the pull request: `docs/releases/vX.Y.Z.md` (the note), `site/releases/index.html`
   (its section, the previous version demoted), `site/releases/latest.json` (version, notes URL,
   **the real publish date**), the site's `softwareVersion`, the Helm chart's versions. Run
   `hack/check-site.py`.
2. Merge. **Wait for `main`'s CI on the squash to be green** before tagging: a tag on a red
   `main` shipped once.
3. `git tag -a vX.Y.Z -m "Zanskar X.Y.Z"` on the squash commit and push the tag. The release
   workflow builds the binaries, the SBOMs, the provenance and the images, signs them, and opens
   a **draft** release.
4. Verify the draft before publishing: every asset present, checksums, `cosign verify-blob`, the
   SLSA provenance, the binary's version and commit, both images for both platforms signed and
   tagged `latest` (the project keeps a verification script for this; it prints one line per
   check). Nothing is published until all of it passes.
5. `gh release edit vX.Y.Z --draft=false --latest`. Then check that the Pages deploy ran and
   `https://albatroxxx.github.io/zanskar/releases/latest.json` reads the new version: every
   gateway's daily update check reads that file.
6. The live gateway is the owner's to upgrade; the note's **Upgrading** section says what to
   back up and what changes posture.

A release candidate stays in the history as a prerelease; a superseded release stays published
and is marked superseded in the notes. The history is never rewritten.

## After a release

The next batch starts on a new branch off `main`. Remote branches of merged pull requests are
deleted; `badges` (CI writes the coverage badge there) and a branch holding an unmerged ADR stay.
