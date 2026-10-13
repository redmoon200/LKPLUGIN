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
blocked() { # the first connection right after a rule change can slip through (documented); the next ones must not
	_slip=0
	for _i in 1 2 3 4; do
		_out=$(cli "curl -sS -o /dev/null -m 8 -w '%{http_code} %{remote_ip}' $1 2>/dev/null" | tr -d '')
		case "$_out" in
		200*)
			echo "    leak on try $_i to ${_out#200 }: $1"
			[ "$_i" -gt 1 ] && return 1
			_slip=1
			opn "sh -c 'pfctl -t l7_blk_1 -T show 2>/dev/null | head -12; tail -6 /var/log/layer7security.log'" | sed 's/^/      /';;
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
started_count() { opn "grep -c started /var/log/layer7security.log" | tr -d '\015'; }
apply() { # wait for the restarted engine to report started: the first request after Apply must not beat it
	_n0=$(started_count)
	api POST /api/layer7security/service/reconfigure | grep -q '"ok"' || return 1
	for _w in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		[ "$(started_count)" != "$_n0" ] && break
		sleep 1
	done
	sleep 3
}
ALLDAYS='"days":"sun,mon,tue,wed,thu,fri,sat","startTime":"00:00","endTime":"00:00"'

# E2E_ONLY="ai geo" runs just those sections (setup always runs); no value runs everything
want() { [ -z "$E2E_ONLY" ] || [ "$1" = setup ] || echo " $E2E_ONLY " | grep -q " $1 "; }

if want setup; then
echo "== setup"
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"enabled":"1","interfaces":"lan","enforce":"1","dnsFilter":"0","dnsCategories":"","dnsBlock":"","dnsAllow":""}}}' >/dev/null
clear_policies
apply
is_running() { api GET /api/layer7security/service/status | grep -q '"running"'; }
check "engine is running" is_running

fi

if want class; then
echo "== classification"
reaches https://www.wikipedia.org >/dev/null; reaches https://github.com >/dev/null; sleep 6
apps=$(api GET "/api/layer7security/dashboard/apps?period=300" | jget "[r['app'] for r in d['rows']]")
has_apps() { echo "$apps" | grep -qi -E 'wikipedia|github|tls'; }
check "dashboard lists observed applications ($apps)" has_apps
flows_found() { api POST /api/layer7security/flows/search '{"current":1,"rowCount":10,"searchPhrase":""}' | python -c "import json,sys; sys.exit(0 if json.load(sys.stdin)['total']>0 else 1)"; }
check "flows search returns rows" flows_found

fi

if want app; then
echo "== block by application (YouTube) for the LAN interface"
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-app\",\"sequence\":\"10\",\"action\":\"block\",\"interfaces\":\"lan\",\"applications\":\"YouTube\",$ALLDAYS}}"
apply
check "YouTube is blocked" blocked https://www.youtube.com
check "control site still reachable" reaches https://www.wikipedia.org
table_filled() { opn 'pfctl -t l7_blk_1 -T show' | grep -q .; }
check "pf table filled" table_filled
dash_blocks() { api GET '/api/layer7security/dashboard/blocks?period=300' | jget "len(d['rows'])" | grep -qv '^0'; }
check "block shows on dashboard" dash_blocks

fi

if want user; then
echo "== block by category for a named user"
clear_policies
api POST /api/layer7security/settings/add_user '{"user":{"name":"alice","addresses":"10.77.0.2"}}' >/dev/null
uid=$(api GET /api/layer7security/settings/search_user | jget "d['rows'][0]['uuid']")
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-user\",\"sequence\":\"10\",\"action\":\"block\",\"users\":\"$uid\",\"categories\":\"SocialNetwork\",$ALLDAYS}}"
apply
check "social network blocked for user alice" blocked https://www.reddit.com
check "other traffic unaffected" reaches https://www.wikipedia.org

fi

if want host; then
echo "== block by host name"
clear_policies
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-host\",\"sequence\":\"10\",\"action\":\"block\",\"interfaces\":\"lan\",\"hosts\":\"github.com\",$ALLDAYS}}"
apply
check "github.com blocked by host name" blocked https://github.com
check "wikipedia still reachable" reaches https://www.wikipedia.org

fi

if want allow; then
echo "== allow policy exempts earlier-sequence match order"
clear_policies
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-allow\",\"sequence\":\"5\",\"action\":\"allow\",\"interfaces\":\"lan\",\"hosts\":\"github.com\",$ALLDAYS}}"
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-deny-all-web\",\"sequence\":\"10\",\"action\":\"block\",\"interfaces\":\"lan\",\"categories\":\"Web,Collaborative\",$ALLDAYS}}"
apply
check "allow policy wins for github.com" reaches https://github.com
check "category block hits other web sites" blocked https://www.wikipedia.org

fi

if want schedule; then
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

fi

if want vlan; then
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

fi

if want geo; then
echo "== GeoIP (needs internet; destinations in DE, FR and the US)"
clear_geo() { for u in $(api GET /api/layer7security/settings/search_geo | python -c "import json,sys; [print(r['uuid']) for r in json.load(sys.stdin)['rows']]" | tr -d ''); do api POST "/api/layer7security/settings/del_geo/$u" >/dev/null; done; }
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

fi

if want mac; then
echo "== MAC binding (client ens4 + throw-away network namespaces)"
clear_policies
cli "cat > /tmp/spoof.sh" < "$(dirname "$0")/../lab/spoof.sh"
cli 'sudo mkdir -p /etc/netns/spoof && echo "nameserver 10.77.0.1" | sudo tee /etc/netns/spoof/resolv.conf >/dev/null'
CMAC=$(cli 'cat /sys/class/net/ens4/address' | tr -d '')
clear_bindings() { for u in $(api GET /api/layer7security/settings/search_binding | python -c "import json,sys; [print(r['uuid']) for r in json.load(sys.stdin)['rows']]" | tr -d ''); do api POST "/api/layer7security/settings/del_binding/$u" >/dev/null; done; }
clear_bindings
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"interfaces":"lan","macMode":"protect","macInterfaces":"lan","macStaticArp":"0"}}}' >/dev/null
api POST /api/layer7security/settings/add_binding "{\"binding\":{\"enabled\":\"1\",\"name\":\"t-client\",\"mac\":\"$CMAC\",\"ip\":\"10.77.0.2\",\"interface\":\"\"}}" >/dev/null
api POST /api/layer7security/settings/add_binding '{"binding":{"enabled":"1","name":"t-phantom","mac":"bc:24:11:99:99:99","ip":"10.77.0.50","interface":""}}' >/dev/null
apply
ns() { cli "sh /tmp/spoof.sh $1 $2" | tr -d ''; }
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

fi

if want ai; then
echo "== AI services (identification, block/allow/monitor, QUIC)"
clear_policies
clear_ai() { for u in $(api GET /api/layer7security/settings/search_ai | python -c "import json,sys; [print(r['uuid']) for r in json.load(sys.stdin)['rows']]" | tr -d ''); do api POST "/api/layer7security/settings/del_ai/$u" >/dev/null; done; }
clear_ai
cli "cat > /tmp/udp.py" < "$(dirname "$0")/../lab/udp443.py"
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"interfaces":"lan","aiEnabled":"1","aiDefault":"monitor","aiQuic":"off"}}}' >/dev/null
apply
ai_up() { [ "$(fetch "$1")" != "000" ]; }
ai_down() {
	for _i in 1 2 3; do
		_out=$(cli "curl -sS -o /dev/null -m 8 -w '%{http_code} %{remote_ip}' $1 2>/dev/null" | tr -d '')
		case "$_out" in
		000*) ;;
		*)
			echo "    leak on try $_i ($_out): $1"
			opn "sh -c 'pfctl -sT | head -20; pfctl -t l7_blk_1 -T show 2>/dev/null | head -8; tail -12 /var/log/layer7security.log'" | sed 's/^/      /'
			[ "$_i" -gt 1 ] && return 1;;
		esac
		sleep 1
	done
	return 0
}
ai_up https://huggingface.co; ai_up https://claude.ai; ai_up https://chatgpt.com; sleep 6
ai_services() { api GET '/api/layer7security/dashboard/ai?period=300' | python -c "import json,sys; s={r['ai'] for r in json.load(sys.stdin)['services']}; sys.exit(0 if {'huggingface','claude','chatgpt'} <= s else 1)"; }
check "monitor: ChatGPT, Claude and Hugging Face are identified by server name" ai_services
ai_event() { api GET /api/layer7security/flows/events | python -c "import json,sys; sys.exit(0 if any(e['type']=='ai-use' and e['app']=='claude' for e in json.load(sys.stdin)['events']) else 1)"; }
check "an ai-use event is logged" ai_event
api POST /api/layer7security/settings/add_ai '{"aiservice":{"enabled":"1","service":"claude","action":"block","inspect":"0","sources":"","users":"","days":"sun,mon,tue,wed,thu,fri,sat","startTime":"00:00","endTime":"00:00"}}' >/dev/null
apply
check "block rule: claude.ai dropped" ai_down https://claude.ai
check "block rule: api.anthropic.com dropped (same service)" ai_down https://api.anthropic.com
check "block rule: other AI services unaffected" ai_up https://huggingface.co
api POST /api/layer7security/settings/add_ai '{"aiservice":{"enabled":"1","service":"chatgpt","action":"allow","inspect":"0","sources":"","users":"","days":"sun,mon,tue,wed,thu,fri,sat","startTime":"00:00","endTime":"00:00"}}' >/dev/null
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"aiDefault":"block"}}}' >/dev/null
apply
check "default block: an explicit allow rule keeps ChatGPT reachable" ai_up https://chatgpt.com
check "default block: other AI services dropped" ai_down https://huggingface.co
check "default block: ordinary sites unaffected" reaches https://www.wikipedia.org
clear_ai
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"aiDefault":"monitor","aiQuic":"all"}}}' >/dev/null
apply
quic_pk() { opn "sh -c 'pfctl -s labels 2>/dev/null | grep l7ai_quic'" | awk '{print $3}'; }
WK=$(cli 'dig +short www.wikipedia.org @10.77.0.1 | grep -E "^[0-9.]+$" | head -1' | tr -d '')
q0=$(quic_pk); cli "python3 /tmp/udp.py $WK"; sleep 1; q1=$(quic_pk)
check "QUIC block (all): UDP/443 datagrams are dropped" test "$((q1 - q0))" -ge 5
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"aiQuic":"ai"}}}' >/dev/null
apply
HF=$(cli 'sudo resolvectl flush-caches; dig +short huggingface.co @10.77.0.1 | grep -E "^[0-9.]+$" | head -1' | tr -d ''); sleep 2
q0=$(quic_pk); cli "python3 /tmp/udp.py $HF"; sleep 1; q1=$(quic_pk); cli "python3 /tmp/udp.py $WK"; sleep 1; q2=$(quic_pk)
check "QUIC block (AI only): datagrams to an AI service are dropped" test "$((q1 - q0))" -ge 5
check "QUIC block (AI only): other UDP/443 traffic is not" test "$((q2 - q1))" -eq 0
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"aiEnabled":"0","aiQuic":"off","aiDefault":"monitor"}}}' >/dev/null

fi

# helpers shared by the AI, audit, inspection and download sections
clear_ai() { for u in $(api GET /api/layer7security/settings/search_ai | python -c "import json,sys; [print(r['uuid']) for r in json.load(sys.stdin)['rows']]" | tr -d '\015'); do api POST "/api/layer7security/settings/del_ai/$u" >/dev/null; done; }
ai_up() { [ "$(fetch "$1")" != "000" ]; }
install_ca() {
	curl -sk -u "$(python -c "import json,sys;d=json.load(open(sys.argv[1]));print(d['key']+':'+d['secret'])" "$(cygpath -w "$LKS/opn_api.json")" | tr -d '\015')" "https://$OPN/api/layer7security/inspection/ca" > /tmp/l7_e2e_ca.crt
	grep -q "BEGIN CERTIFICATE" /tmp/l7_e2e_ca.crt || return 1
	cli "sudo tee /usr/local/share/ca-certificates/layer7-inspection.crt >/dev/null && sudo update-ca-certificates >/dev/null 2>&1" < /tmp/l7_e2e_ca.crt
}

if want audit; then
echo "== AI audit log (privacy gate, masked records, hash chain, export)"
clear_policies
api POST /api/layer7security/audit/ack >/dev/null
api POST /api/layer7security/audit/set '{"layer7security":{"audit":{"enabled":"1","retentionDays":"365","syslogLocal":"1","syslogTarget":"","noticeText":""}}}' >/dev/null
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"interfaces":"lan","aiEnabled":"1","aiDefault":"monitor","aiQuic":"off"}}}' >/dev/null
apply
ai_up https://claude.ai; ai_up https://chatgpt.com; sleep 8
opn 'configctl layer7security audit-ingest' >/dev/null
aud_has() { api POST /api/layer7security/audit/search '{"current":1,"rowCount":50,"searchPhrase":"","period":3600}' | python -c "import json,sys; sys.exit(0 if any(r['kind']=='ai-use' for r in json.load(sys.stdin)['rows']) else 1)"; }
check "AI use is recorded in the audit log" aud_has
aud_ok() { api GET /api/layer7security/audit/verify | python -c "import json,sys; sys.exit(0 if json.load(sys.stdin)['ok'] else 1)"; }
check "the hash chain verifies" aud_ok
opnsh <<'EOF' > /tmp/audit_tamper.out
cd /usr/local/opnsense/scripts/OPNsense/Layer7Security
cp /var/db/layer7security/audit.db /tmp/audit_copy.db
python3 -c "
import sqlite3
c=sqlite3.connect('/tmp/audit_copy.db')
c.execute(\"UPDATE audit SET detail='edited' WHERE seq=(SELECT MIN(seq)+2 FROM audit)\")
c.commit()"
L7_AUDIT_DB=/tmp/audit_copy.db python3 audit.py verify tamper-test
rm -f /tmp/audit_copy.db
EOF
check "an edited record is detected" grep -q '"ok": false' /tmp/audit_tamper.out
exp_ok() {
	api GET '/api/layer7security/audit/export?format=jsonl&period=3600' | opn 'cat > /tmp/audit_export.jsonl' || return 1
	opn 'sh -c "cd /usr/local/opnsense/scripts/OPNsense/Layer7Security && python3 audit.py verify-file /tmp/audit_export.jsonl"' | grep -q '"ok": true'
}
check "an export verifies offline" exp_ok
api POST /api/layer7security/audit/set '{"layer7security":{"audit":{"enabled":"0"}}}' >/dev/null
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"aiEnabled":"0"}}}' >/dev/null

fi

if want inspect; then
echo "== AI content inspection (selective TLS bump, DLP, masking)"
clear_policies
clear_ai
api POST /api/layer7security/audit/ack >/dev/null
api POST /api/layer7security/audit/set '{"layer7security":{"audit":{"enabled":"1","retentionDays":"365","syslogLocal":"1","syslogTarget":"","noticeText":""}}}' >/dev/null
api POST /api/layer7security/settings/add_ai '{"aiservice":{"enabled":"1","service":"claude","action":"monitor","inspect":"1","sources":"","users":"","days":"sun,mon,tue,wed,thu,fri,sat","startTime":"00:00","endTime":"00:00"}}' >/dev/null
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"interfaces":"lan","aiEnabled":"1","aiDefault":"monitor","aiQuic":"off"},"dlp":{"enabled":"1","inspectDefault":"0","cardAction":"block","idAction":"block","keyAction":"block","codeAction":"monitor","codeMinLines":"12","failMode":"closed","maxBodyKb":"4096","blockMessage":""}}}' >/dev/null
apply
sleep 3
check "the CA certificate can be downloaded and installed" install_ca
ca_limited() { api GET /api/layer7security/inspection/ca_info | grep -q anthropic.com; }
check "the CA is restricted to named domains" ca_limited
proxy_up() { api GET /api/layer7security/inspection/status | grep -q '"running":true'; }
check "the inspection proxy is running" proxy_up
cli 'sudo resolvectl flush-caches; dig +short api.anthropic.com @10.77.0.1 >/dev/null'; sleep 2
post() { cli "curl -sS -m 12 -o /dev/null -w '%{http_code}' -H 'content-type: application/json' -d '$1' https://api.anthropic.com/v1/messages 2>/dev/null"; }
CARDMSG='{"messages":[{"role":"user","content":"my card is 4111 1111 1111 1111"}]}'
KEYMSG='{"p":"key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz01"}'
CLEANMSG='{"messages":[{"role":"user","content":"hello there"}]}'
check "a card number is blocked" test "$(post "$CARDMSG")" = 403
check "an API key is blocked" test "$(post "$KEYMSG")" = 403
r=$(post "$CLEANMSG")
check "a clean request reaches the real service (got $r)" sh -c "[ '$r' != 403 ] && [ '$r' != 000 ]"
issuer() { cli "echo | openssl s_client -connect $1:443 -servername $1 2>/dev/null | openssl x509 -noout -issuer"; }
check "only the selected service is decrypted (Wikipedia keeps its certificate)" sh -c "! echo \"$(issuer www.wikipedia.org)\" | grep -q 'Layer 7'"
check "the selected service presents the inspection certificate" sh -c "echo \"$(issuer api.anthropic.com)\" | grep -q 'Layer 7'"
opn 'configctl layer7security audit-ingest' >/dev/null
api POST /api/layer7security/audit/search '{"current":1,"rowCount":20,"searchPhrase":"","period":3600}' > /tmp/audit_rows.json
check "the block is audited with a masked snippet" sh -c "grep -q dlp-block /tmp/audit_rows.json && grep -q '1111' /tmp/audit_rows.json"
check "the audit log never holds the raw card number" sh -c "! grep -q '4111 1111 1111 1111' /tmp/audit_rows.json"
api POST /api/layer7security/settings/set '{"layer7security":{"dlp":{"cardAction":"monitor"}}}' >/dev/null
apply; sleep 2
c=000; for _i in 1 2 3 4 5 6; do c=$(post "$CARDMSG"); [ "$c" != 000 ] && break; sleep 3; done
check "monitor mode lets the card through (got $c)" sh -c "[ '$c' != 403 ] && [ '$c' != 000 ]"
api POST /api/layer7security/settings/set '{"layer7security":{"dlp":{"enabled":"0"}}}' >/dev/null
apply
no_bump() { for _i in 1 2 3 4 5 6; do opn 'pfctl -sn' | grep -q l7_ai_bump || return 0; sleep 3; done; return 1; }
check "disabled: no traffic is redirected to the proxy" no_bump
clear_ai
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"aiEnabled":"0"}}}' >/dev/null

fi

if want av; then
echo "== Download protection (file types, hash feed, EICAR, HTTPS)"
clear_policies
api POST /api/layer7security/audit/ack >/dev/null
opnsh <<'EOF'
mkdir -p /tmp/avsrv
rm -f /var/db/layer7security/av_hashes.txt /var/db/layer7security/av_feed.json
python3 - <<'PY'
d = '/tmp/avsrv'
open(d + '/eicar.com', 'wb').write(('X5O!P%@AP[4' + chr(92) + 'PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*').encode())
open(d + '/program.jpg', 'wb').write(b'MZ' + b'\x90\x00' * 200)
open(d + '/tool.sh', 'wb').write(b'#!/bin/sh\necho hello\n')
open(d + '/notes.txt', 'wb').write(b'plain text file\n')
PY
pkill -f "http.server 80 --bind 198.51.100.10" 2>/dev/null
ifconfig lo0 alias 198.51.100.10/32 2>/dev/null
cd /tmp/avsrv && daemon -f -p /var/run/avtest.pid python3 -m http.server 80 --bind 198.51.100.10
sleep 1
EOF
av_set() { api POST /api/layer7security/settings/set "{\"layer7security\":{\"av\":$1}}" >/dev/null; }
av_get() { cli "curl -sS -m 10 -o /tmp/av.out -w '%{http_code}' http://198.51.100.10/$1 2>/dev/null"; }
av_set '{"enabled":"1","scanHttp":"1","httpsDomains":"","hashAction":"block","executableAction":"monitor","scriptAction":"monitor","packageAction":"monitor","archiveAction":"off","customHashes":"","feedUrl":"","feedAuthKey":"","feedHours":"24","skipDomains":"","maxSizeMb":"50","failMode":"open"}'
apply; sleep 2
check "an ordinary file is delivered" test "$(av_get notes.txt)" = 200
check "the EICAR test file is blocked" test "$(av_get eicar.com)" = 403
page_reason() { cli 'grep -c EICAR /tmp/av.out' | grep -q 1; }
check "the block page names the reason" page_reason
check "file types in monitor mode are delivered" test "$(av_get program.jpg)" = 200
av_set '{"executableAction":"block"}'; apply; sleep 2
check "a program disguised as a picture is blocked by file type" test "$(av_get program.jpg)" = 403
av_set '{"executableAction":"monitor"}'
opnsh <<'EOF'
printf '# lab feed\n%s\n' "$(sha256 -q /tmp/avsrv/tool.sh)" > /tmp/avsrv/feed.txt
EOF
av_set '{"feedUrl":"http://198.51.100.10/feed.txt"}'; apply; sleep 2
feed_ok() { api POST /api/layer7security/antivirus/feed_update | grep -q '"updated":true'; }
check "the hash feed downloads" feed_ok
sleep 22
check "a file whose hash is in the feed is blocked" test "$(av_get tool.sh)" = 403
av_det() { api POST /api/layer7security/antivirus/search '{"current":1,"rowCount":50,"searchPhrase":"","period":3600}' | python -c "import json,sys; r=json.load(sys.stdin)['rows']; sys.exit(0 if any(x['action']=='blocked' and x['file']=='eicar.com' for x in r) and any(x['action']=='observed' for x in r) else 1)"; }
check "detections are listed (blocked and logged)" av_det
not_ours() { ! cli "echo | openssl s_client -connect github.com:443 -servername github.com 2>/dev/null | openssl x509 -noout -issuer" | grep -q 'Layer 7'; }
check "unrelated HTTPS traffic keeps its certificate" not_ours
av_set '{"httpsDomains":"secure.eicar.org"}'
r=$(api POST /api/layer7security/service/reconfigure)
if echo "$r" | grep -q "not allowed to sign"; then
	ok "an HTTPS site outside the CA is refused until the CA is replaced"
	api POST /api/layer7security/inspection/ca_new >/dev/null
else
	ok "the CA already covers the HTTPS site"
fi
apply
install_ca
cli 'sudo resolvectl flush-caches; dig +short secure.eicar.org @10.77.0.1 >/dev/null'; sleep 3
sget() { cli "curl -sS -m 15 -o /dev/null -w '%{http_code}' https://secure.eicar.org/eicar.com.txt 2>/dev/null"; }
https_blocked() { for _i in 1 2 3; do [ "$(sget)" = 403 ] && return 0; sleep 2; done; return 1; }
check "EICAR over HTTPS is blocked on a selected site" https_blocked
av_set '{"enabled":"0","httpsDomains":"","feedUrl":""}'
apply
opnsh <<'EOF'
pkill -f "http.server 80 --bind 198.51.100.10"
ifconfig lo0 -alias 198.51.100.10 2>/dev/null
rm -rf /tmp/avsrv /var/run/avtest.pid
EOF

fi

if want dns; then
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

fi

if want cleanup; then
echo "== cleanup"
clear_policies
apply
no_rules() { ! opn 'pfctl -sr' | grep -q l7_blk; }
check "no policy left in pf" no_rules

fi

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
