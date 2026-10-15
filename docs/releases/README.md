# Cutting a release

Notes for each release live beside this file as `vX.Y.Z.md`; the release workflow
prepends that file to the GitHub release it drafts, so the name must equal the tag.

1. Land everything on `main` and let CI pass.
2. Write `docs/releases/vX.Y.Z.md`; add the version's section to `site/releases/index.html`
   and keep the page's description within the site check's limits
   (`python3 hack/check-site.py`).
3. Point the site's manifest at the release: `site/releases/latest.json` carries the
   `version`, the `notes_url` (the releases page anchor) and `published_at`. Gateways read
   this file once a day to light the bell, so it is bumped with the release, never before.
4. Update the JSON-LD `softwareVersion` on the home page and the chart's `appVersion`.
5. Retake the console screenshots: build with `-tags webui` and
   `-ldflags "-X github.com/albatroxxx/zanskar/internal/version.Version=X.Y.Z"`, then
   `SHOT_DIR=... bash hack/screenshots/seed.sh` and `node hack/screenshots/shoot.mjs …`
   (the script's header has the arguments); replace the `*-X.Y.Z.jpg` references.
6. Merge, `git pull`, `git tag vX.Y.Z && git push origin vX.Y.Z`; the workflow builds a
   draft with signed checksums, SBOMs and SLSA provenance.
7. Review the draft's assets, publish, then run the image scan workflow so the
   published image's alerts update.
