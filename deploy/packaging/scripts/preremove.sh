#!/bin/sh
# Stop and disable the service on real removal, but not during an upgrade.
#   deb:  $1="remove"/"purge" on removal, "upgrade" during upgrade
#   rpm:  $1=0 on final removal, 1 during upgrade
set -e

case "$1" in
	remove | purge | 0)
		systemctl disable --now zanskar >/dev/null 2>&1 || true
		systemctl disable --now zanskar-update.path >/dev/null 2>&1 || true
		systemctl disable --now zanskar-config.path >/dev/null 2>&1 || true
		;;
esac
