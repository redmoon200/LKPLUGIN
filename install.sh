#!/bin/sh
# Install or update the Layer 7 Security plugin on OPNsense from the GitHub releases.
#
#   fetch -qo - https://raw.githubusercontent.com/redmoon200/LKPLUGIN/main/install.sh | sh
#   sh install.sh 0.6.0        (a specific version)
#
# Run it as root on the firewall (console or SSH, option 8 "Shell"). It installs what the plugin needs from the
# OPNsense package repository (ndpi, sqlite3, squid, yara), then the plugin package from this repository's release.
# Safe to run again: it updates an installed plugin and keeps its settings.

REPO=redmoon200/LKPLUGIN
SUPPORTED_ABI=26.1

say() { echo "install.sh: $*"; }
die() { echo "install.sh: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run this as root"
command -v opnsense-version >/dev/null 2>&1 || die "this is not an OPNsense firewall"

abi=$(opnsense-version -a 2>/dev/null)
case "$abi" in
	"$SUPPORTED_ABI"*) ;;
	*) die "this plugin build is for OPNsense $SUPPORTED_ABI (this firewall reports '$abi'). A build for newer releases is not available yet." ;;
esac

version=${1:-}
if [ -z "$version" ]; then
	version=$(fetch -qo - "https://api.github.com/repos/$REPO/releases" 2>/dev/null | grep -o '"tag_name": *"v[0-9][0-9.]*"' | head -1 | grep -o '[0-9][0-9.]*')
	[ -n "$version" ] || die "could not find the newest release (is the firewall online?). Try: sh install.sh 0.6.0"
fi
url="https://github.com/$REPO/releases/download/v$version/os-layer7security-$version.pkg"
say "installing plugin version $version"

say "refreshing the package catalog"
pkg update -q || die "pkg update failed (does the firewall have internet access?)"
say "installing the dependencies from the OPNsense repository"
pkg install -y ndpi sqlite3 squid yara || die "could not install the dependencies"
say "installing the plugin from $url"
pkg add -f "$url" || die "the plugin package could not be installed"

installed=$(pkg query %v os-layer7security 2>/dev/null)
[ "$installed" = "$version" ] || die "expected version $version but the package manager reports '$installed'"
say "done: os-layer7security $installed is installed"
say "next: open the web interface, Layer 7 > License, enter the feed server address and a license key."
