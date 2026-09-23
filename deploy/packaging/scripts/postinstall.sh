#!/bin/sh
# Create the state and config directories, refresh systemd, and (on a fresh
# install only) print how to configure and start the service. The package never
# auto-starts: the unit requires /etc/zanskar/env, which the admin creates with
# `zanskar init`.
set -e

install -d -o zanskar -g zanskar -m 0750 /var/lib/zanskar
install -d -o zanskar -g zanskar -m 0750 /var/lib/zanskar/recordings
install -d -m 0755 /etc/zanskar

systemctl daemon-reload >/dev/null 2>&1 || true

# Detect a first install vs an upgrade.
#   deb:  $1=configure, $2=previously-configured version (empty on first install)
#   rpm:  $1=1 on install, 2 on upgrade
fresh=0
case "$1" in
	configure) [ -z "$2" ] && fresh=1 ;;
	1) fresh=1 ;;
esac

if [ "$fresh" = 1 ] && [ ! -f /etc/zanskar/env ]; then
	cat <<'MSG'

Zanskar is installed but not started. To configure and start it:

  sudo zanskar init                      # writes /etc/zanskar/env (master key, TLS, paths)
  sudo systemctl enable --now zanskar

Or copy /etc/zanskar/env.example to /etc/zanskar/env, edit it, then enable the
service. Put a TLS-terminating reverse proxy (Caddy/nginx) in front. See
/usr/share/doc/zanskar or https://github.com/albatroxxx/zanskar.

MSG
fi
