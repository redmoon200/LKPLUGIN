#!/bin/sh
# Install the l7cloud server on an Ubuntu/Debian host (run as root).
#   sh install.sh            installs under /opt/l7cloud: the feed server (port 8080),
#                            the dashboard with the license generator (port 8090) and an
#                            hourly list rebuild. On the first run it creates the vendor
#                            signing key and prints the dashboard password once.
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
id l7cloud >/dev/null 2>&1 || useradd --system --home /var/lib/l7cloud --shell /usr/sbin/nologin l7cloud
# yara is used only to test that every signature file compiles before it is published
command -v yarac >/dev/null 2>&1 || apt-get install -y yara >/dev/null 2>&1 || echo "note: yara not installed, signature files are published unchecked"
install -d -o l7cloud -g l7cloud /var/lib/l7cloud /var/lib/l7cloud/feeds
install -d /opt/l7cloud/server /opt/l7cloud/data /opt/l7cloud/data/yara
install -m 755 "$SRC"/server/*.py /opt/l7cloud/server/
install -m 644 "$SRC/server/dashboard.html" /opt/l7cloud/server/
cp "$SRC"/data/*.txt /opt/l7cloud/data/ 2>/dev/null || true
cp "$SRC"/data/yara/*.yar /opt/l7cloud/data/yara/ 2>/dev/null || true
install -m 644 "$SRC"/systemd/*.service "$SRC"/systemd/*.timer /etc/systemd/system/
systemctl daemon-reload
# signing key and dashboard password (first run only); the output is shown once
sudo -u l7cloud python3 /opt/l7cloud/server/dashboard.py init
chmod 700 /var/lib/l7cloud/license
# first build before serving, then keep rebuilding every hour
sudo -u l7cloud python3 /opt/l7cloud/server/build_feeds.py --data /opt/l7cloud/data
systemctl enable --now l7cloud-feed.service l7cloud-dashboard.service l7cloud-build.timer
# an upgrade must not leave the old code running
systemctl restart l7cloud-feed.service l7cloud-dashboard.service
ip="$(hostname -I | awk '{print $1}')"
echo "feeds:     http://$ip:8080/feeds/manifest.json"
echo "dashboard: http://$ip:8090/   (user: the password printed above; keep the signing key /var/lib/l7cloud/license/signing.pem backed up offline)"
