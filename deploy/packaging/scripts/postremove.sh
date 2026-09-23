#!/bin/sh
# Refresh systemd after the unit file is gone. The database and recordings in
# /var/lib/zanskar and the `zanskar` system user are deliberately left in place
# so a reinstall keeps existing data; remove them by hand to fully purge.
set -e

systemctl daemon-reload >/dev/null 2>&1 || true
