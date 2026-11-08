# License helpers for the end-to-end tests (sourced by e2e.sh).
# The plugin must be licensed for the suite to run. Give it a key from your vendor in the environment:
#   L7_LICENSE_KEY=ABCDE-FGHIJ-... sh tests/e2e.sh
# (a key that is tied to one firewall must be issued for the installation id shown on Layer 7 > License).
# The suite needs jget() and api() from e2e.sh / lab/env.sh.

lic_state() { api GET /api/layer7security/license/status | jget "d['license']['state']"; }
fw_install_id() { api GET /api/layer7security/license/status | jget "d['license']['install_id']"; }
lic_activate() { # key -> prints "OK message" or "NO message"
	api POST /api/layer7security/license/activate "{\"key\":\"$1\"}" | jget "('OK ' if d.get('ok') else 'NO ') + d.get('message','')"
}
# make sure the firewall runs with a valid license (a fresh install is locked)
lic_ensure() {
	[ "$(lic_state)" = valid ] && return 0
	if [ -z "$L7_LICENSE_KEY" ]; then
		echo "  (the firewall has no valid license: set L7_LICENSE_KEY to a license key from your vendor; installation id $(fw_install_id))"
		return 1
	fi
	lic_activate "$L7_LICENSE_KEY" >/dev/null
	[ "$(lic_state)" = valid ]
}
