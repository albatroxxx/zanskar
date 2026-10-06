#!/bin/sh
# Create the state and config directories, refresh systemd, and (on a fresh
# install only) print how to configure and start the service. The package never
# auto-starts: the unit requires /etc/zanskar/env, which the admin creates with
# `zanskar init`.
set -e

install -d -o zanskar -g zanskar -m 0750 /var/lib/zanskar
install -d -o zanskar -g zanskar -m 0750 /var/lib/zanskar/recordings
install -d -m 0755 /etc/zanskar
# The running service reads the env file back to tell the console when it
# changed (a restart is then due), so an existing file becomes group-readable.
if [ -f /etc/zanskar/env ]; then
	chown root:zanskar /etc/zanskar/env 2>/dev/null || true
	chmod 0640 /etc/zanskar/env 2>/dev/null || true
fi

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

  # 1. Write /etc/zanskar/env (master key, TLS, paths). It prints the next steps.
  sudo zanskar init

  # 2. Apply migrations and create the first admin, as the zanskar user so it
  #    owns the database files. admin create asks for the password twice
  #    without echo; keep it off the command line (shell history).
  sudo bash -c 'set -a; . /etc/zanskar/env; set +a; \
    runuser -u zanskar -- zanskar migrate && \
    runuser -u zanskar -- zanskar admin create --username admin --name "Your Name"'

  # 3. Start the service.
  sudo systemctl enable --now zanskar

By default the gateway then serves HTTPS on 443 with a self-signed certificate
(port 80 redirects there); upload a real certificate in Settings, or run
`zanskar init -behind-proxy` to sit behind Caddy/nginx instead.
Install guide: https://albatroxxx.github.io/zanskar/docs/

MSG
fi
