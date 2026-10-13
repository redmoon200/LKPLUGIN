# Source me: shell helpers for the lab VMs. Secrets stay in ~/.lk-secrets (not in the repo).
LKS="$HOME/.lk-secrets"
LK_KEY="$LKS/id_ed25519_lk"
LK_SSH="-i $LK_KEY -o IdentitiesOnly=yes -o BatchMode=yes -o UserKnownHostsFile=$LKS/lab_known_hosts -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8"
OPN=192.168.1.12     # OPNsense WAN address (DHCP lease; see docs/PROGRESS.md)
CLIENT=192.168.1.72  # client mgmt
CLOUD=192.168.1.73   # cloud server
opn()    { ssh $LK_SSH root@$OPN "$@"; }
opnsh()  { ssh $LK_SSH root@$OPN 'sh -s'; }          # script on stdin (root shell is csh)
cli()    { ssh $LK_SSH lk@$CLIENT "$@"; }
cloud()  { ssh $LK_SSH lk@$CLOUD "$@"; }
# call the OPNsense API with the lab key (stored outside the repo): api GET|POST path [json]
api() {
  _m="$1"; _p="$2"; _d="$3"
  _f="$LKS/opn_api.json"; command -v cygpath >/dev/null 2>&1 && _f=$(cygpath -w "$_f")
  _k=$(python -c "import json,sys;print(json.load(open(sys.argv[1]))['key'])" "$_f" | tr -d '\015')
  _s=$(python -c "import json,sys;print(json.load(open(sys.argv[1]))['secret'])" "$_f" | tr -d '\015')
  [ "$_m" = POST ] && [ -z "$_d" ] && _d="{}"
  _body="${TMPDIR:-/tmp}/api_body.$$"
  for _try in 1 2 3; do
    if [ -n "$_d" ]; then
      API_CODE=$(curl -sk -m 90 -o "$_body" -w '%{http_code}' -u "$_k:$_s" -X "$_m" -H 'Content-Type: application/json' -d "$_d" "https://$OPN$_p")
    else
      API_CODE=$(curl -sk -m 90 -o "$_body" -w '%{http_code}' -u "$_k:$_s" -X "$_m" "https://$OPN$_p")
    fi
    API_RC=$?
    [ -s "$_body" ] && break
    sleep 2
  done
  cat "$_body" 2>/dev/null; echo
  rm -f "$_body"
}
