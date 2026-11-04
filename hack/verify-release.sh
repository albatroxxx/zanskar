#!/bin/bash
# Verify a draft release before it is published (docs/working/batches-and-releases.md):
# every asset present, the checksums, the cosign signature on them, the SLSA provenance of
# the archives, the binary's version and commit, and both images on both platforms, signed,
# with `latest` pointing at this version. One line per check; read them all before
# `gh release edit vX.Y.Z --draft=false --latest`.
#
# Usage: hack/verify-release.sh 1.18.0
# Needs: gh (signed in), cosign, slsa-verifier, docker, go.
set -u
V=${1:?version, e.g. 1.18.0}
T=v$V
REPO=${ZANSKAR_REPO:-albatroxxx/zanskar}
ID="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$T"
ISSUER=https://token.actions.githubusercontent.com
D=$(mktemp -d -t zanskar-rel-"$V")
trap 'rm -rf "$D"' EXIT
cd "$D" || exit 1

gh release download "$T" -R "$REPO" -p 'SHA256SUMS*' -p '*.tar.gz' -p 'zanskar.intoto.jsonl' -p '*.deb' >/dev/null
echo "== assets: $(gh release view "$T" -R "$REPO" --json assets --jq '.assets | length')"
echo "== checksums"; shasum -a 256 -c SHA256SUMS --ignore-missing 2>&1 | tail -6
echo "== cosign blob"; cosign verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" SHA256SUMS 2>&1 | tail -1
echo "== slsa"
for a in zanskar_"${V}"_linux_amd64.tar.gz zanskar_"${V}"_linux_arm64.tar.gz; do
  slsa-verifier verify-artifact "$a" --provenance-path zanskar.intoto.jsonl --source-uri "github.com/$REPO" --source-tag "$T" 2>&1 | tail -1
done
echo "== binary"; mkdir x && tar -xzf zanskar_"${V}"_linux_amd64.tar.gz -C x && go version -m x/zanskar | grep -E "^x/zanskar|vcs.revision|vcs.modified|-X " | head -5
echo "== images"
for img in zanskar zanskar-browser; do
  ref="ghcr.io/${REPO%/*}/$img"
  arch=$(docker manifest inspect "$ref:$V" 2>&1 | grep -c '"architecture": "a')
  a=$(docker manifest inspect "$ref:$V" 2>&1 | grep '"digest"' | sort | tr -d ' \n')
  b=$(docker manifest inspect "$ref:latest" 2>&1 | grep '"digest"' | sort | tr -d ' \n')
  if [ -n "$a" ] && [ "$a" = "$b" ]; then echo "$img: $arch platforms, latest == $V"; else echo "$img: $arch platforms, latest DIFFERS or empty"; fi
  if cosign verify "$ref:$V" --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" >/dev/null 2>&1; then echo "$img: signed ok"; else echo "$img: signature FAILED"; fi
done
