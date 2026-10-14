# Sections added in 0.5.0 (license and cloud dashboard). Sourced by e2e.sh after the 0.4.0 sections.

engine_up() { opn 'pgrep -f libexec/layer7security/l7engine' >/dev/null 2>&1; }
api_locked() { api GET /api/layer7security/settings/get >/dev/null; [ "$API_CODE" = 402 ]; }
msg_has() { echo "$1" | grep -q "$2"; }
tomorrow() { python -c "import datetime; print((datetime.date.today()+datetime.timedelta(days=1)).isoformat())"; }
sync_cloud() { api POST /api/layer7security/license/sync '{}' >/dev/null; }
set_fw_clock() { # epoch seconds -> sets the firewall's clock (UTC)
	opn "sh -c 'date -u \$(date -u -j -r $1 +%Y%m%d%H%M.%S) >/dev/null'"
}
lic_check() { opn '/usr/local/opnsense/scripts/OPNsense/Layer7Security/license.php check' >/dev/null; }
dash_field() { dash GET "$1" | jget "$2"; }

if want lic; then
echo "== License: lock, trial, key rules, revoke, replace, expiry, clock rollback, cloud dashboard"
INST=$(fw_install_id)
inst_ok() { echo "$INST" | grep -Eq '^[0-9A-F]{4}(-[0-9A-F]{4}){3}$'; }
check "the installation id looks like 1234-ABCD-5678-EF01 ($INST)" inst_ok
dash_ok() { dash_login; }
check "the cloud dashboard accepts the admin password" dash_ok

echo "-- no license: protection off, network untouched"
api POST /api/layer7security/license/remove '{}' >/dev/null
check "state is none without a key" test "$(lic_state)" = none
engine_down() { ! engine_up; }
check "the engine process is gone" engine_down
check "Layer 7 APIs answer 'license required' (402)" api_locked
check "the license API itself still works" test "$(lic_state)" = none
check "the client still reaches the internet" reaches http://192.168.1.73:8080/health
no_pf() { ! opn 'pfctl -sr' | grep -q l7_blk; }
check "no Layer 7 block rule is left in pf" no_pf

echo "-- keys that must be refused"
r=$(lic_activate "$(python -c "print('-'.join(['ABCDE']*40))")")
check "garbage is not a key ($r)" msg_has "$r" '^NO '
other=$(lic_issue year "e2e other firewall" 1234-ABCD-5678-EF01 | cut -d' ' -f1)
r=$(lic_activate "$other")
check "a key tied to another firewall is refused ($r)" msg_has "$r" 'another firewall'
old=$(lic_issue year "e2e expired" "$INST" 2024-01-01 | cut -d' ' -f1)
r=$(lic_activate "$old")
check "an expired key is refused ($r)" msg_has "$r" 'expired'
check "the state is still none" test "$(lic_state)" = none
bad_input() { dash POST /api/licenses/issue '{"type":"forever","customer":"x"}' | grep -q '"error"'; }
check "the generator refuses an unknown license type" bad_input

echo "-- trial"
r=$(api POST /api/layer7security/license/trial '{}' | jget "d.get('message')")
check "a 30 day trial can be started ($r)" test "$(lic_state)/$(lic_type)" = valid/trial
check "the engine is running again" engine_up
unlocked() { api GET /api/layer7security/settings/get >/dev/null; [ "$API_CODE" = 200 ]; }
check "Layer 7 APIs answer again (200)" unlocked
days=$(api GET /api/layer7security/license/status | jget "d['license']['days_left']")
check "the trial has about 30 days ($days)" test "$days" -ge 29 -a "$days" -le 30
api POST /api/layer7security/license/remove '{}' >/dev/null
r=$(api POST /api/layer7security/license/trial '{}' | jget "d.get('ok')")
check "asking again gives the same trial back" test "$r" = True
api POST /api/layer7security/license/remove '{}' >/dev/null
dash POST /api/settings '{"trials_enabled":false}' >/dev/null
r=$(api POST /api/layer7security/license/trial '{}' | jget "d.get('message')")
check "with trials switched off the server refuses ($r)" msg_has "$r" 'switched off'
dash POST /api/settings '{"trials_enabled":true}' >/dev/null
r=$(api POST /api/layer7security/license/trial '{}' | jget "d.get('ok')")
check "trials work again once enabled" test "$r" = True

echo "-- renewal and replacement rules"
y1=$(lic_issue year "e2e year" "$INST" | cut -d' ' -f1)
r=$(lic_activate "$y1")
check "a 1 year key replaces the shorter trial ($r)" test "$(lic_type)" = year
r=$(lic_activate "$y1")
check "the same key again does not run longer ($r)" msg_has "$r" 'run longer'
y0=$(lic_issue year "e2e older" "$INST" "$(python -c "import datetime; print((datetime.date.today()-datetime.timedelta(days=30)).isoformat())")" | cut -d' ' -f1)
r=$(lic_activate "$y0")
check "an older key is refused ($r)" msg_has "$r" 'run longer'
y2=$(lic_issue year "e2e renewal" "$INST" "$(tomorrow)" | cut -d' ' -f1)
r=$(lic_activate "$y2")
check "a key that ends later is accepted ($r)" msg_has "$r" '^OK '
unbound=$(lic_issue lifetime "e2e lifetime any firewall" | cut -d' ' -f1)
r=$(lic_activate "$unbound")
check "a lifetime key replaces a yearly one ($r)" test "$(lic_type)" = lifetime
r=$(lic_activate "$y2")
check "a lifetime license cannot be replaced ($r)" msg_has "$r" 'cannot be replaced'
r=$(lic_activate "$unbound")
check "not even by another lifetime key" msg_has "$r" 'cannot be replaced'
bound=$(api GET /api/layer7security/license/status | jget "d['license']['bound']")
check "the unbound lifetime key works on this firewall (bound=$bound)" test "$bound" = False

echo "-- the vendor withdraws and replaces a license"
api POST /api/layer7security/license/remove '{}' >/dev/null
yr=$(lic_issue year "e2e revoke" "$INST")
yrkey=${yr% *}; yrid=${yr#* }
lic_activate "$yrkey" >/dev/null
check "a bound yearly key is accepted" test "$(lic_state)" = valid
dash POST /api/licenses/revoke "{\"key_id\":\"$yrid\",\"revoked\":true}" >/dev/null
sync_cloud
check "after the next check-in the withdrawn license locks the firewall" test "$(lic_state)" = revoked
engine_down2() { ! engine_up; }
check "protection is off again" engine_down2
check "the APIs are locked" api_locked
dash POST /api/licenses/revoke "{\"key_id\":\"$yrid\",\"revoked\":false}" >/dev/null
sync_cloud
check "reinstating the license unlocks it at the next check-in" test "$(lic_state)" = valid
check "the engine is running again after reinstating" engine_up
rep=$(dash POST /api/licenses/replace "{\"key_id\":\"$yrid\",\"type\":\"lifetime\",\"install_id\":\"$INST\"}" | python -c "import json,sys; print(json.load(sys.stdin)['license']['key_id'])" | tr -d '\015')
sync_cloud
check "a replacement issued by the vendor is installed by the check-in" test "$(lic_type)" = lifetime

echo "-- clock: a license that ends, and a clock that was turned back"
api POST /api/layer7security/license/remove '{}' >/dev/null
lic_activate "$(lic_issue year "e2e clock" "$INST" | cut -d' ' -f1)" >/dev/null
check "a yearly key is active before the clock tests" test "$(lic_state)" = valid
T0=$(fw_time); S0=$SECONDS
set_fw_clock $((T0 + 100 * 86400))
lic_check
check "100 days later the license is still valid" test "$(lic_state)" = valid
set_fw_clock $((T0 + SECONDS - S0))
lic_check
st=$(lic_state)
check "turning the clock back is noticed ($st)" test "$st" = rollback
check "protection is off while the clock is wrong" engine_down2
sync_cloud
check "the cloud server confirms the clock and the license is valid again" test "$(lic_state)" = valid
T1=$(fw_time); S1=$SECONDS
set_fw_clock $((T1 + 400 * 86400))
lic_check
st=$(lic_state)
check "after more than a year the license has expired ($st)" test "$st" = expired
check "the engine is stopped when the license ends" engine_down2
set_fw_clock $((T1 + SECONDS - S1))
sleep 2
sync_cloud
lic_check
check "with the right time again the license runs on ($(lic_state))" test "$(lic_state)" = valid
check "and the engine is back" engine_up

echo "-- cloud dashboard"
no_login() { [ "$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H 'X-Requested-With: l7dash' $DASH/api/overview)" = 401 ]; }
check "the dashboard API needs a login" no_login
no_csrf() { [ "$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST -d '{}' $DASH/api/login)" = 403 ]; }
check "a POST without the dashboard header is refused" no_csrf
wrong_pw() { [ "$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST -H 'X-Requested-With: l7dash' -d '{"password":"nope"}' $DASH/api/login)" = 401 ]; }
check "a wrong password is refused" wrong_pw
fw_listed() { dash GET /api/firewalls | python -c "import json,sys; sys.exit(0 if any(r['install_id']=='$INST' for r in json.load(sys.stdin)['rows']) else 1)"; }
check "the firewall is listed with its installation id" fw_listed
fw_online() { dash GET /api/firewalls | python -c "import json,sys; sys.exit(0 if any(r['install_id']=='$INST' and r['online'] and r['version'] for r in json.load(sys.stdin)['rows']) else 1)"; }
check "it shows as online with its version" fw_online
check "the overview counts firewalls" test "$(dash_field /api/overview "d['firewalls']['total']")" -ge 1
check "the overview knows the last build ($(dash_field /api/overview "d['build'].get('ok')"))" test "$(dash_field /api/overview "d['build'].get('ok')")" = True
check "the feeds page lists the published files" test "$(dash_field /api/feeds "len(d['files'])")" -gt 20
api_rows() { dash GET '/api/activity?kind=api&limit=50' | python -c "import json,sys; rows=json.load(sys.stdin)['rows']; sys.exit(0 if any(r['path']=='/api/v1/checkin' and r['status']==200 for r in rows) else 1)"; }
check "the activity log shows the check-ins" api_rows
bad_checkin() { [ "$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"install_id":"zz"}' http://192.168.1.73:8080/api/v1/checkin)" = 400 ]; }
check "the server rejects a check-in without a valid installation id" bad_checkin
big_checkin() { python -c "print('{\"x\":\"' + 'a'*20000 + '\"}')" | curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary @- http://192.168.1.73:8080/api/v1/checkin | grep -q 400; }
check "an oversized body is refused" big_checkin
csv_ok() { dash GET /api/licenses.csv | head -1 | grep -q '^key_id,type'; }
check "the license list exports as CSV" csv_ok
pub_ok() {
	_f="$(dirname "$0")/../security/layer7security/src/opnsense/mvc/app/library/OPNsense/Layer7Security/License.php"
	_embedded=$(grep -o "PUBKEY_B64 = '[^']*" "$_f" | cut -d"'" -f2)
	_served=$(dash GET /api/pubkey | python -c "import json,sys; print(json.load(sys.stdin)['b64'])" | tr -d '\015')
	[ -n "$_embedded" ] && [ "$_embedded" = "$_served" ]
}
check "the plugin embeds the dashboard's public key" pub_ok

echo "-- back to a lifetime license for the other sections"
api POST /api/layer7security/license/remove '{}' >/dev/null
lic_ensure
check "a lifetime license is active again" test "$(lic_state)/$(lic_type)" = valid/lifetime
check "and the engine is running" engine_up

fi
