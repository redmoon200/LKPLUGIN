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
		_out=$(cli "curl -sS -o /dev/null -m 8 -w '%{http_code} %{remote_ip}' $1 2>/dev/null" | tr -d '')
		case "$_out" in
		200*)
			echo "    leak on try $_i to ${_out#200 }: $1"
			opn "sh -c 'pfctl -t l7_blk_1 -T show 2>/dev/null | head -12; tail -6 /var/log/layer7security.log'" | sed 's/^/      /'
			return 1;;
		esac
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
	vlan_flows() { api POST /api/layer7security/flows/search '{"current":1,"rowCount":100,"searchPhrase":"10.88.0.2","period":300}' | python -c "
import json,sys
t0=int(sys.argv[1]); d=json.load(sys.stdin)
rows=[r for r in d['rows'] if r['ts_start']>=t0]
bad=[r for r in rows if r['iface']!='vlan0.10']
if not rows or bad:
    for r in (bad or rows)[:6]: print('    offending:', r['iface'], r['client'], '->', r['server'], r['app'], 'start+%d' % (r['ts_start']-t0), file=sys.stderr)
    print('    rows after T0:', len(rows), file=sys.stderr)
    sys.exit(1)" "$T0"; }
	check "VLAN flows are recorded on vlan0.10 only (no double counting)" vlan_flows
	api POST /api/layer7security/settings/set '{"layer7security":{"general":{"interfaces":"lan"}}}' >/dev/null
else
	echo "  SKIP no VLAN on the client"
fi

echo "== GeoIP (needs internet; destinations in DE, FR and the US)"
clear_geo() { for u in $(api GET /api/layer7security/settings/search_geo | python -c "import json,sys; [print(r['uuid']) for r in json.load(sys.stdin)['rows']]" | tr -d ''); do api POST "/api/layer7security/settings/del_geo/$u" >/dev/null; done; }
geo_url_ok() { [ "$(fetch "$1")" != "000" ]; }
geo_blocked() { for _i in 1 2; do [ "$(fetch "$1")" != "000" ] && return 1; done; return 0; }
clear_policies; clear_geo
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"interfaces":"lan","geoEnabled":"1"}}}' >/dev/null
if ! opn 'test -s /var/db/layer7security/geo/v4.tsv && echo yes' | grep -q yes; then
	api POST /api/layer7security/geo/update >/dev/null
fi
DE=https://www.hetzner.com; DE2=https://www.bund.de; FR=https://www.ovh.com; US=https://www.wikipedia.org
if geo_url_ok $DE && geo_url_ok $FR && geo_url_ok $US; then
	api POST /api/layer7security/settings/add_geo '{"geopolicy":{"enabled":"1","name":"t-geo-block","action":"block","direction":"out","interfaces":"lan","countries":"DE","exceptions":"","log":"0"}}' >/dev/null
	apply
	check "geo block: Germany is dropped" geo_blocked $DE
	check "geo block: France still reachable" geo_url_ok $FR
	check "geo block: the US still reachable" geo_url_ok $US
	geo_counter() { opn "sh -c 'pfctl -s labels 2>/dev/null | grep l7geo_1_out'" | awk '{exit !($3 > 0)}'; }
	check "pf rule counter shows dropped packets" geo_counter
	clear_geo
	api POST /api/layer7security/settings/add_geo '{"geopolicy":{"enabled":"1","name":"t-geo-allow","action":"allow","direction":"out","interfaces":"lan","countries":"FR","exceptions":"213.133.116.44/32","log":"0"}}' >/dev/null
	apply
	check "allow-only FR: France reachable" geo_url_ok $FR
	check "allow-only FR: the exception (a German host) reachable" geo_url_ok $DE
	check "allow-only FR: another German site dropped" geo_blocked $DE2
	check "allow-only FR: the US dropped" geo_blocked $US
	check "allow-only FR: DNS through the firewall still works" test "$(dns_status github.com)" = NOERROR
	clear_geo
	apply
	cli 'for h in www.hetzner.com www.ovh.com www.wikipedia.org; do curl -sS -o /dev/null -m 6 https://$h 2>/dev/null; done' >/dev/null
	sleep 6
	geo_flows() { api POST /api/layer7security/flows/search '{"current":1,"rowCount":50,"searchPhrase":"hetzner","period":300}' | python -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if any(r['country']=='DE' for r in d['rows']) else 1)"; }
	check "flows are tagged with the server country (DE)" geo_flows
	geo_dash() { api GET '/api/layer7security/dashboard/countries?period=300' | python -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if {'DE','FR'} <= {r['country'] for r in d['rows']} else 1)"; }
	check "dashboard top countries include DE and FR" geo_dash
else
	echo "  SKIP destinations not reachable"
fi
clear_geo
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"geoEnabled":"0"}}}' >/dev/null

echo "== MAC binding (client ens4 + throw-away network namespaces)"
clear_policies
cli "cat > /tmp/spoof.sh" < "$(dirname "$0")/../lab/spoof.sh"
cli 'sudo mkdir -p /etc/netns/spoof && echo "nameserver 10.77.0.1" | sudo tee /etc/netns/spoof/resolv.conf >/dev/null'
CMAC=$(cli 'cat /sys/class/net/ens4/address' | tr -d '')
clear_bindings() { for u in $(api GET /api/layer7security/settings/search_binding | python -c "import json,sys; [print(r['uuid']) for r in json.load(sys.stdin)['rows']]" | tr -d ''); do api POST "/api/layer7security/settings/del_binding/$u" >/dev/null; done; }
clear_bindings
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"interfaces":"lan","macMode":"protect","macInterfaces":"lan","macStaticArp":"0"}}}' >/dev/null
api POST /api/layer7security/settings/add_binding "{\"binding\":{\"enabled\":\"1\",\"name\":\"t-client\",\"mac\":\"$CMAC\",\"ip\":\"10.77.0.2\",\"interface\":\"\"}}" >/dev/null
api POST /api/layer7security/settings/add_binding '{"binding":{"enabled":"1","name":"t-phantom","mac":"bc:24:11:99:99:99","ip":"10.77.0.50","interface":""}}' >/dev/null
apply
ns() { cli "sh /tmp/spoof.sh $1 $2" | tr -d ''; }
ns_ok() { ns "$1" "$2" | grep -q "http 200"; }
ns_dropped() { ns "$1" "$2" | grep -q "http 000"; }
anchor_loaded() { opn 'pfctl -a l7sec_ether -s ether' | grep -q "from 10.77.0.50"; }
check "ether rules are loaded in the l7sec_ether anchor" anchor_loaded
check "protect: the bound client keeps working" reaches https://www.wikipedia.org
check "protect: a device with the right MAC and IP works" ns_ok bc:24:11:99:99:99 10.77.0.50
check "protect: the same IP from another MAC is dropped" ns_dropped 02:aa:bb:cc:dd:ee 10.77.0.50
check "protect: an unbound IP is still allowed" ns_ok 02:aa:bb:cc:dd:ee 10.77.0.60
spoof_event() { api GET /api/layer7security/flows/events | python -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if any(e['type']=='mac-spoof' and e['client']=='10.77.0.50' for e in d['events']) else 1)"; }
check "the engine raised a mac-spoof event" spoof_event
dev_states() { api GET '/api/layer7security/dashboard/devices?period=3600' | python -c "
import json,sys
st={(r['ip'],r['mac']):r['state'] for r in json.load(sys.stdin)['rows']}
ok = st.get(('10.77.0.50','bc:24:11:99:99:99'))=='bound' and st.get(('10.77.0.50','02:aa:bb:cc:dd:ee'))=='spoof' and st.get(('10.77.0.60','02:aa:bb:cc:dd:ee'))=='unbound'
sys.exit(0 if ok else 1)"; }
check "discovered devices are classified bound / spoof / unbound" dev_states
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"macMode":"strict"}}}' >/dev/null
apply
check "strict: the bound client keeps working" reaches https://www.wikipedia.org
check "strict: an unknown device is dropped" ns_dropped 02:aa:bb:cc:dd:ee 10.77.0.60
api POST /api/layer7security/settings/add_binding '{"binding":{"enabled":"1","name":"t-guest","mac":"02:aa:bb:cc:dd:ee","ip":"","interface":""}}' >/dev/null
apply
check "strict: a MAC-only binding lets that device on" ns_ok 02:aa:bb:cc:dd:ee 10.77.0.60
check "strict: ... but it cannot take over a bound IP" ns_dropped 02:aa:bb:cc:dd:ee 10.77.0.50
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"macMode":"protect","macStaticArp":"1"}}}' >/dev/null
apply
static_arp() { opn 'arp -an' | grep "(10.77.0.50)" | grep -q permanent; }
check "static ARP: bound addresses get permanent entries" static_arp
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"macMode":"off"}}}' >/dev/null
clear_bindings
apply
anchor_gone() { ! opn 'pfctl -a l7sec_ether -s ether' | grep -q "ether"; }
check "off: the anchor is empty again" anchor_gone
check "off: the client still works" reaches https://www.wikipedia.org

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
