#!/bin/sh
# End-to-end test against the lab: OPNsense firewall (9101) + client (9102).
# Drives the plugin only through its REST API and checks the effect from the
# client. Needs lab/env.sh and the API key in ~/.lk-secrets/opn_api.json.
#
#   tests/e2e.sh        run everything, exit 1 if any check fails
. "$(dirname "$0")/../lab/env.sh"

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); echo "  PASS $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL $1"; }
check() { # description, command...
	_d="$1"; shift
	if "$@"; then ok "$_d"; else bad "$_d"; fi
}

jget()  { python -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1" | tr -d '\015'; }
fetch() { cli "curl -sS -o /dev/null -m 8 -w '%{http_code}' $1 2>/dev/null"; }
reaches() { [ "$(fetch "$1")" = "200" ]; }
blocked() { # a few tries: an address is learned on first contact, then dropped
	for _i in 1 2 3; do
		[ "$(fetch "$1")" = "200" ] && return 1
		sleep 2
	done
	return 0
}
dns_status() { cli "dig +time=3 +tries=1 $1 @10.77.0.1 | grep -o 'status: [A-Z]*' | cut -d' ' -f2"; }

clear_policies() {
	for u in $(api GET /api/layer7security/settings/search_policy | python -c "import json,sys; [print(r['uuid']) for r in json.load(sys.stdin)['rows']]" | tr -d '\015'); do
		_r=$(api POST "/api/layer7security/settings/del_policy/$u")
		case "$_r" in *deleted*) ;; *) echo "  (delete $u failed: [$_r] http=$API_CODE)";; esac
	done
	for u in $(api GET /api/layer7security/settings/search_user | python -c "import json,sys; [print(r['uuid']) for r in json.load(sys.stdin)['rows']]" | tr -d '\015'); do
		api POST "/api/layer7security/settings/del_user/$u" >/dev/null
	done
}
add_policy() { api POST /api/layer7security/settings/add_policy "$1" >/dev/null; }
apply() { api POST /api/layer7security/service/reconfigure | grep -q '"ok"' && sleep 3; }
ALLDAYS='"days":"sun,mon,tue,wed,thu,fri,sat","startTime":"00:00","endTime":"00:00"'

echo "== setup"
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"enabled":"1","interfaces":"lan","enforce":"1","dnsFilter":"0","dnsCategories":"","dnsBlock":"","dnsAllow":""}}}' >/dev/null
clear_policies
apply
is_running() { api GET /api/layer7security/service/status | grep -q '"running"'; }
check "engine is running" is_running

echo "== classification"
reaches https://www.wikipedia.org >/dev/null; reaches https://github.com >/dev/null; sleep 6
apps=$(api GET "/api/layer7security/dashboard/apps?period=300" | jget "[r['app'] for r in d['rows']]")
has_apps() { echo "$apps" | grep -qi -E 'wikipedia|github|tls'; }
check "dashboard lists observed applications ($apps)" has_apps
flows_found() { api POST /api/layer7security/flows/search '{"current":1,"rowCount":10,"searchPhrase":""}' | python -c "import json,sys; sys.exit(0 if json.load(sys.stdin)['total']>0 else 1)"; }
check "flows search returns rows" flows_found

echo "== block by application (YouTube) for the LAN interface"
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-app\",\"sequence\":\"10\",\"action\":\"block\",\"interfaces\":\"lan\",\"applications\":\"YouTube\",$ALLDAYS}}"
apply
check "YouTube is blocked" blocked https://www.youtube.com
check "control site still reachable" reaches https://www.wikipedia.org
table_filled() { opn 'pfctl -t l7_blk_1 -T show' | grep -q .; }
check "pf table filled" table_filled
dash_blocks() { api GET '/api/layer7security/dashboard/blocks?period=300' | jget "len(d['rows'])" | grep -qv '^0'; }
check "block shows on dashboard" dash_blocks

echo "== block by category for a named user"
clear_policies
api POST /api/layer7security/settings/add_user '{"user":{"name":"alice","addresses":"10.77.0.2"}}' >/dev/null
uid=$(api GET /api/layer7security/settings/search_user | jget "d['rows'][0]['uuid']")
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-user\",\"sequence\":\"10\",\"action\":\"block\",\"users\":\"$uid\",\"categories\":\"SocialNetwork\",$ALLDAYS}}"
apply
check "social network blocked for user alice" blocked https://www.reddit.com
check "other traffic unaffected" reaches https://www.wikipedia.org

echo "== block by host name"
clear_policies
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-host\",\"sequence\":\"10\",\"action\":\"block\",\"interfaces\":\"lan\",\"hosts\":\"github.com\",$ALLDAYS}}"
apply
check "github.com blocked by host name" blocked https://github.com
check "wikipedia still reachable" reaches https://www.wikipedia.org

echo "== allow policy exempts earlier-sequence match order"
clear_policies
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-allow\",\"sequence\":\"5\",\"action\":\"allow\",\"interfaces\":\"lan\",\"hosts\":\"github.com\",$ALLDAYS}}"
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-deny-all-web\",\"sequence\":\"10\",\"action\":\"block\",\"interfaces\":\"lan\",\"categories\":\"Web,Collaborative\",$ALLDAYS}}"
apply
check "allow policy wins for github.com" reaches https://github.com
check "category block hits other web sites" blocked https://www.wikipedia.org

echo "== schedule"
clear_policies
now=$(opn "date +%H:%M")
h=${now%:*}; m=${now#*:}
off_s=$(printf '%02d:00' $(( (10#$h + 6) % 24 ))); off_e=$(printf '%02d:00' $(( (10#$h + 7) % 24 )))
on_s=$(printf '%02d:00' $(( (10#$h + 23) % 24 ))); on_e=$(printf '%02d:00' $(( (10#$h + 1) % 24 )))
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-off\",\"sequence\":\"10\",\"action\":\"block\",\"interfaces\":\"lan\",\"hosts\":\"github.com\",\"days\":\"sun,mon,tue,wed,thu,fri,sat\",\"startTime\":\"$off_s\",\"endTime\":\"$off_e\"}}"
apply
check "outside the window nothing is blocked ($off_s-$off_e, now $now)" reaches https://github.com
clear_policies
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-on\",\"sequence\":\"10\",\"action\":\"block\",\"interfaces\":\"lan\",\"hosts\":\"github.com\",\"days\":\"sun,mon,tue,wed,thu,fri,sat\",\"startTime\":\"$on_s\",\"endTime\":\"$on_e\"}}"
apply
check "inside the window github.com is blocked ($on_s-$on_e, now $now)" blocked https://github.com

echo "== per-VLAN policy (needs the lab VLAN: lab/make-vlan.php + client ens4.10)"
if [ "$(cli 'ip -br a show ens4.10 2>/dev/null | wc -l' | tr -d '')" = "1" ]; then
	clear_policies
	api POST /api/layer7security/settings/set '{"layer7security":{"general":{"interfaces":"lan,opt1"}}}' >/dev/null
	add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-vlan\",\"sequence\":\"10\",\"action\":\"block\",\"interfaces\":\"opt1\",\"applications\":\"YouTube\",$ALLDAYS}}"
	apply
	T0=$(opn 'date +%s' | tr -d '')
	vlan_blocked() { for _i in 1 2 3; do [ "$(cli "curl -sS -o /dev/null -m 6 --interface 10.88.0.2 -w '%{http_code}' https://www.youtube.com 2>/dev/null")" = 200 ] && return 1; done; return 0; }
	lan_open() { [ "$(cli "curl -sS -o /dev/null -m 8 --interface 10.77.0.2 -w '%{http_code}' https://www.youtube.com 2>/dev/null")" = 200 ]; }
	vlan_control() { [ "$(cli "curl -sS -o /dev/null -m 8 --interface 10.88.0.2 -w '%{http_code}' https://www.wikipedia.org 2>/dev/null")" = 200 ]; }
	check "YouTube blocked for VLAN 10 clients" vlan_blocked
	check "YouTube still open for the LAN" lan_open
	check "VLAN 10 control site reachable" vlan_control
	T0=$(opn 'date +%s' | tr -d '')
	vlan_flows() { api POST /api/layer7security/flows/search '{"current":1,"rowCount":100,"searchPhrase":"10.88.0.2","period":300}' | python -c "
import json,sys
t0=int(sys.argv[1]); d=json.load(sys.stdin)
rows=[r for r in d['rows'] if r['ts_start']>=t0]
sys.exit(0 if rows and all(r['iface']=='vlan0.10' for r in rows) else 1)" "$T0"; }
	check "VLAN flows are recorded on vlan0.10 only (no double counting)" vlan_flows
	api POST /api/layer7security/settings/set '{"layer7security":{"general":{"interfaces":"lan"}}}' >/dev/null
else
	echo "  SKIP no VLAN on the client"
fi

echo "== DNS filtering, global and per group"
clear_policies
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"dnsFilter":"1","dnsMode":"nxdomain","dnsCategories":"ads","dnsBlock":"blocked-test.example","dnsAllow":""}}}' >/dev/null
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-dns-a\",\"sequence\":\"10\",\"action\":\"block\",\"sources\":\"10.77.0.0/24\",\"dnsDomains\":\"example.net\",$ALLDAYS}}"
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-dns-b\",\"sequence\":\"20\",\"action\":\"block\",\"sources\":\"10.99.0.0/24\",\"dnsDomains\":\"example.org\",$ALLDAYS}}"
apply
check "global category list blocks doubleclick.net" test "$(dns_status doubleclick.net)" = NXDOMAIN
check "global custom domain blocked" test "$(dns_status blocked-test.example)" = NXDOMAIN
check "group A domain blocked for group A client" test "$(dns_status example.net)" = NXDOMAIN
check "group B domain not blocked for group A client" test "$(dns_status example.org)" = NOERROR
check "normal lookup works" test "$(dns_status github.com)" = NOERROR
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"dnsFilter":"0","dnsCategories":"","dnsBlock":""}}}' >/dev/null

echo "== cleanup"
clear_policies
apply
no_rules() { ! opn 'pfctl -sr' | grep -q l7_blk; }
check "no policy left in pf" no_rules

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
