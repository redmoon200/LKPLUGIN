#!/bin/sh
# Copy engine sources to the OPNsense lab VM and build there.
. "$(dirname "$0")/env.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
tar -C "$ROOT" -cf - engine | opn "sh -c 'rm -rf /root/engine && tar -C /root -xf - && cd /root/engine && make 2>&1 | tail -40'"
