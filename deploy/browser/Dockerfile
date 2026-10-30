# syntax=docker/dockerfile:1.7
# The isolated browser an application session runs in (ADR 0034): Debian's
# Chromium in kiosk mode behind TigerVNC's X server, as an unprivileged user.
# The gateway starts one per session, read-only, without capabilities, under
# a seccomp profile that lets Chromium's own sandbox work, on a network
# where the only other thing is the session's relay. Built and published
# by release.yml as ghcr.io/albatroxxx/zanskar-browser:<version>.
#
# Trimmed (1.9.0): Mesa's software GL with LLVM, Perl and Chromium's Vulkan
# validation layer are taken out after the install. Chromium runs with
# --disable-gpu and draws in software, and the entrypoint starts Xvnc
# itself, so none of them is used: about 660 MB on disk instead of 900 MB,
# a 270 MB download instead of 340 MB. The build fails if one comes back
# under a new name.
FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
# packages lists what the layer below installs. PACKAGES is a digest of the
# versions apt would install from it, worked out by release.yml before the
# build: when it matches the last release's, the layer comes from that
# release's build cache unchanged, and an upgrade downloads only the layers
# after it. A new Chromium or library changes the digest and rebuilds it.
COPY packages /usr/share/zanskar-browser/packages
ARG PACKAGES=unknown
RUN echo "packages $PACKAGES" \
 && apt-get update \
 && xargs -a /usr/share/zanskar-browser/packages apt-get install -y --no-install-recommends \
 && dpkg --purge --force-depends libllvm19 mesa-libgallium libz3-4 libgl1-mesa-dri perl libperl5.40 perl-modules-5.40 \
 && ! dpkg -l 'libllvm*' 'mesa-libgallium*' 'libgl1-mesa-dri*' 'libperl*' 'perl-modules*' 2>/dev/null | grep '^ii' \
 && rm -rf /var/lib/apt/lists/* /usr/lib/chromium/libVkLayer_khronos_validation.so \
 && useradd -m -u 10001 -s /usr/sbin/nologin browser \
 && mkdir -p /etc/chromium/policies/managed
COPY entrypoint.sh /entrypoint.sh
# The VNC server listens on 5900 for the session relay alone; nothing is
# published and there is no EXPOSE: the relay reaches it on the session network.
USER browser
ENV HOME=/tmp/home
ENTRYPOINT ["/entrypoint.sh"]
