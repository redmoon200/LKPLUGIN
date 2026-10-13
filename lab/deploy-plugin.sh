#!/bin/sh
# Build the engine and install engine + plugin files on the OPNsense lab VM.
# Mirrors what the package does: src/ maps to /usr/local.
. "$(dirname "$0")/env.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
set -e
"$ROOT/lab/deploy-engine.sh" | tail -2
tar -C "$ROOT/security/layer7security/src" -cf - . | opn "sh -c 'tar --no-same-owner -C /usr/local -xf -'"
opnsh <<'REMOTE'
mkdir -p /usr/local/libexec/layer7security
install -m 755 /root/engine/l7engine /usr/local/libexec/layer7security/l7engine
chmod 755 /usr/local/etc/rc.d/layer7security
chmod 755 /usr/local/opnsense/scripts/OPNsense/Layer7Security/*
rm -f /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
service configd restart >/dev/null 2>&1
service php_fpm restart >/dev/null 2>&1
echo deployed
REMOTE
