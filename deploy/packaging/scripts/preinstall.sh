#!/bin/sh
# Create the unprivileged system user/group the gateway runs as. Idempotent so
# it is safe on reinstall and upgrade.
set -e

if ! getent group zanskar >/dev/null 2>&1; then
	groupadd --system zanskar
fi

if ! getent passwd zanskar >/dev/null 2>&1; then
	nologin=/usr/sbin/nologin
	[ -x "$nologin" ] || nologin=/sbin/nologin
	[ -x "$nologin" ] || nologin=/bin/false
	useradd --system --gid zanskar --home-dir /var/lib/zanskar \
		--no-create-home --shell "$nologin" \
		--comment "Zanskar access gateway" zanskar
fi
