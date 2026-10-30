#!/usr/bin/env bash
# Build the browser image (ADR 0034) for one architecture so that an
# unchanged set of packages reuses an earlier build's package layer:
#
#   deploy/browser/build.sh <arch> <tag> [<cache image>] [docker build flags...]
#
# PACKAGES, the Dockerfile's cache key for that layer, is a digest of the
# versions apt would install from deploy/browser/packages on the Dockerfile's
# base, worked out here before the build. When it matches the cache image's,
# BuildKit takes the layer from that image's inline cache: the same blob, so
# a host upgrading between the two downloads only the layers after it. A new
# Chromium or library changes the digest and the layer is built afresh.
# release.yml caches from the last release's image; ci.yml proves the round
# trip through a registry on the runner.
set -euo pipefail

dir=$(cd "$(dirname "$0")" && pwd)
arch=$1 tag=$2 cache=${3:-}
shift $(($# < 3 ? $# : 3))

base=$(sed -n 's/^FROM //p' "$dir/Dockerfile")
packages=$(docker run --rm --platform "linux/$arch" -v "$dir/packages:/packages:ro" "$base" \
  sh -c 'apt-get update -qq >/dev/null && xargs -a /packages apt-get install -s --no-install-recommends' |
  grep '^Inst ' | sort | sha256sum | cut -c1-16)
echo "browser image packages: $packages" >&2

from=()
if [[ -n "$cache" ]]; then
  if docker pull --quiet --platform "linux/$arch" "$cache" >/dev/null 2>&1; then
    from=(--cache-from "$cache")
  else
    echo "no $cache to take the package layer from; building it" >&2
  fi
fi
docker build --platform "linux/$arch" ${from[@]+"${from[@]}"} \
  --build-arg BUILDKIT_INLINE_CACHE=1 --build-arg PACKAGES="$packages" \
  "$@" -t "$tag" "$dir"
