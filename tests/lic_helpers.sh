# License helpers for the end-to-end tests (sourced by e2e.sh). They talk to the cloud dashboard
# (license generator) with the admin password from ~/.lk-secrets/cloud_admin.txt and to the plugin through its API.

DASH=${DASH:-http://192.168.1.73:8090}
DASH_JAR=${TEMP:-/tmp}/l7dash.jar

dash_login() {
	_pw=$(tr -d '\r\n' < "$HOME/.lk-secrets/cloud_admin.txt")
	rm -f "$DASH_JAR"
	curl -s -m 15 -c "$DASH_JAR" -H 'X-Requested-With: l7dash' -H 'Content-Type: application/json' \
		-d "{\"password\":\"$_pw\"}" "$DASH/api/login" | grep -q '"ok"'
}
dash() { # method path [json]
	[ -f "$DASH_JAR" ] || dash_login
	if [ -n "$3" ]; then
		curl -s -m 20 -b "$DASH_JAR" -X "$1" -H 'X-Requested-With: l7dash' -H 'Content-Type: application/json' -d "$3" "$DASH$2"
	else
		curl -s -m 20 -b "$DASH_JAR" -X "$1" -H 'X-Requested-With: l7dash' "$DASH$2"
	fi
}
fw_install_id() { api GET /api/layer7security/license/status | jget "d['license']['install_id']"; }
lic_state() { api GET /api/layer7security/license/status | jget "d['license']['state']"; }
lic_type() { api GET /api/layer7security/license/status | jget "d['license']['type']"; }
# lic_issue type customer [install id|-] [issued yyyy-mm-dd]  -> prints "<key> <key id>"
lic_issue() {
	_inst=""; [ "${3:--}" != "-" ] && _inst="$3"
	_date=""; [ -n "$4" ] && _date="$4"
	dash POST /api/licenses/issue "{\"type\":\"$1\",\"customer\":\"$2\",\"install_id\":\"$_inst\",\"issued\":\"$_date\",\"note\":\"e2e\"}" |
		python -c "import json,sys; d=json.load(sys.stdin)['license']; print(d['key'], d['key_id'])" | tr -d '\015'
}
lic_activate() { # key -> prints the answer's message
	api POST /api/layer7security/license/activate "{\"key\":\"$1\"}" | jget "('OK ' if d.get('ok') else 'NO ') + d.get('message','')"
}
# make sure the firewall runs with a lifetime license (a fresh install is locked)
lic_ensure() {
	[ "$(lic_state)" = valid ] && [ "$(lic_type)" = lifetime ] && return 0
	_inst=$(fw_install_id)
	_lkey=$(lic_issue lifetime "e2e lifetime" "$_inst" | cut -d' ' -f1)
	api POST /api/layer7security/license/remove '{}' >/dev/null
	lic_activate "$_lkey" >/dev/null
	[ "$(lic_state)" = valid ]
}
fw_time() { opn 'date -u +%s' | tr -d '\015'; }
