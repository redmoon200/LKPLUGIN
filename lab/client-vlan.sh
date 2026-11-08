#!/bin/sh
# Lab client: VLAN 10 on the test NIC plus the policy route that sends traffic with source 10.88.0.2 out through it.
# Without the route that traffic leaves untagged on the LAN port (wrong interface, dropped as spoofed), and the
# per-VLAN section of tests/e2e.sh fails. Needs lab/make-vlan.php to have been run on the firewall (and a reboot).
# Not persistent: run it again after the client restarts.
. "$(dirname "$0")/env.sh"
cli 'sudo sh -s' <<'REMOTE'
ip link show ens4.10 >/dev/null 2>&1 || ip link add link ens4 name ens4.10 type vlan id 10
ip addr show ens4.10 | grep -q 10.88.0.2 || ip addr add 10.88.0.2/24 dev ens4.10
ip link set ens4.10 up
ip route replace default via 10.88.0.1 dev ens4.10 table 10
ip rule show | grep -q 'from 10.88.0.2 lookup 10' || ip rule add from 10.88.0.2 table 10
ip -br a show ens4.10
ip rule show | grep 10.88.0.2
REMOTE
