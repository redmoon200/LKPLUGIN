#!/bin/sh
# Build os-layer7security-<version>.pkg on the OPNsense lab VM with the
# opnsense/plugins build framework (stable/26.1). The compiled engine is
# staged into the plugin tree so the package carries it.
#
#   lab/build-package.sh      result: dist/os-layer7security-*.pkg
. "$(dirname "$0")/env.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
set -e

"$ROOT/lab/deploy-engine.sh" | tail -1

# 1. framework (read-only reference clone kept on the VM)
opnsh <<'REMOTE'
[ -d /root/plugins ] || git clone -q --depth 1 -b stable/26.1 https://github.com/opnsense/plugins.git /root/plugins
rm -rf /root/plugins/security/layer7security
mkdir -p /root/plugins/security/layer7security
REMOTE

# 2. plugin tree (no stray ownership)
tar --exclude=__pycache__ -C "$ROOT/security/layer7security" -cf - . | opn "sh -c 'tar --no-same-owner -C /root/plugins/security/layer7security -xf -'"

# 3. stage the engine binary and build the package
opnsh <<'REMOTE'
cd /root/plugins/security/layer7security
mkdir -p src/libexec/layer7security
install -m 755 /root/engine/l7engine src/libexec/layer7security/l7engine
chmod 755 src/etc/rc.d/layer7security src/etc/rc.d/layer7security_proxy src/etc/rc.d/layer7security_portal src/opnsense/scripts/OPNsense/Layer7Security/*
make clean >/dev/null 2>&1 || true
make package 2>&1 | tail -15
ls -la work/pkg/ 2>/dev/null
REMOTE

# 4. fetch the package
mkdir -p "$ROOT/dist"
opn "sh -c 'cat /root/plugins/security/layer7security/work/pkg/os-layer7security-*.pkg'" > "$ROOT/dist/os-layer7security.pkg"
ls -la "$ROOT/dist"
