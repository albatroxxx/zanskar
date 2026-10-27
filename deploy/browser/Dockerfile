# syntax=docker/dockerfile:1.7
# The isolated browser an application session runs in (ADR 0034): Debian's
# Chromium in kiosk mode behind TigerVNC's X server, as an unprivileged user.
# The gateway starts one per session, read-only, without capabilities, under
# a seccomp profile that lets Chromium's own sandbox work, on a network
# where the only other thing is the session's relay. Built and published
# by release.yml as ghcr.io/albatroxxx/zanskar-browser:<version>.
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      chromium tigervnc-standalone-server tigervnc-tools libnss3-tools \
      fonts-dejavu-core fonts-liberation fonts-noto-core ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 10001 -s /usr/sbin/nologin browser \
 && mkdir -p /etc/chromium/policies/managed
COPY entrypoint.sh /entrypoint.sh
USER browser
ENV HOME=/tmp/home
EXPOSE 5900
ENTRYPOINT ["/entrypoint.sh"]
