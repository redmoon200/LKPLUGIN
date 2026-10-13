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
