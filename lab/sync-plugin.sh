#!/bin/sh
# Copy only the plugin files (no engine build) to the OPNsense lab VM: for quick GUI/PHP/Python iterations.
. "$(dirname "$0")/env.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
set -e
tar --exclude=__pycache__ -C "$ROOT/security/layer7security/src" -cf - . | opn "sh -c 'tar --no-same-owner -C /usr/local -xf -'"
opnsh <<'REMOTE'
chmod 755 /usr/local/etc/rc.d/layer7security /usr/local/etc/rc.d/layer7security_proxy /usr/local/etc/rc.d/layer7security_portal
chmod 755 /usr/local/opnsense/scripts/OPNsense/Layer7Security/*
rm -f /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json
service configd restart >/dev/null 2>&1
service php_fpm restart >/dev/null 2>&1
echo synced
REMOTE
