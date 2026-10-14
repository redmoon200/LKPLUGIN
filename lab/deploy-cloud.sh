#!/bin/sh
# Copy only the cloud server code to the cloud VM and restart its services (no list rebuild).
. "$(dirname "$0")/env.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
set -e
tar --exclude=__pycache__ -C "$ROOT/cloud" -cf - server systemd | cloud 'rm -rf /tmp/l7c-up && mkdir /tmp/l7c-up && tar -C /tmp/l7c-up -xf -'
cloud 'sudo install -m 755 /tmp/l7c-up/server/*.py /opt/l7cloud/server/ && sudo install -m 644 /tmp/l7c-up/server/dashboard.html /opt/l7cloud/server/ && sudo install -m 644 /tmp/l7c-up/systemd/*.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl restart l7cloud-feed l7cloud-dashboard && sleep 1 && systemctl is-active l7cloud-feed l7cloud-dashboard'
