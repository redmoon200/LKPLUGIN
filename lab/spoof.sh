#!/bin/sh
# usage: spoof.sh MAC IP  -> curl wikipedia from a throwaway namespace using that MAC and IP
MAC=$1; IP=$2
sudo ip netns del spoof 2>/dev/null; sudo ip link del sp0 2>/dev/null
sudo ip netns add spoof
sudo ip link add link ens4 name sp0 type macvlan mode bridge
sudo ip link set sp0 address "$MAC"
sudo ip link set sp0 netns spoof
sudo ip netns exec spoof ip link set lo up
sudo ip netns exec spoof ip addr add "$IP/24" dev sp0
sudo ip netns exec spoof ip link set sp0 up
sudo ip netns exec spoof ip route add default via 10.77.0.1
sudo ip netns exec spoof ip neigh flush all 2>/dev/null
R=$(sudo ip netns exec spoof curl -sS -o /dev/null -m 6 -w '%{http_code}' https://www.wikipedia.org 2>/dev/null)
[ -z "$R" ] && R=000
echo "ns mac=$MAC ip=$IP -> http $R"
sudo ip netns del spoof 2>/dev/null
