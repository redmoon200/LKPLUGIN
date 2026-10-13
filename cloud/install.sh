#!/bin/sh
# Install the l7cloud feed server on an Ubuntu/Debian host (run as root).
#   sh install.sh            installs under /opt/l7cloud, enables the feed
#                            server and an hourly list rebuild
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
id l7cloud >/dev/null 2>&1 || useradd --system --home /var/lib/l7cloud --shell /usr/sbin/nologin l7cloud
# yara is used only to test that every signature file compiles before it is published
command -v yarac >/dev/null 2>&1 || apt-get install -y yara >/dev/null 2>&1 || echo "note: yara not installed, signature files are published unchecked"
install -d -o l7cloud -g l7cloud /var/lib/l7cloud /var/lib/l7cloud/feeds
install -d /opt/l7cloud/server /opt/l7cloud/data /opt/l7cloud/data/yara
install -m 755 "$SRC/server/feedserver.py" "$SRC/server/build_feeds.py" /opt/l7cloud/server/
cp "$SRC"/data/*.txt /opt/l7cloud/data/ 2>/dev/null || true
cp "$SRC"/data/yara/*.yar /opt/l7cloud/data/yara/ 2>/dev/null || true
install -m 644 "$SRC/systemd/l7cloud-feed.service" "$SRC/systemd/l7cloud-build.service" \
	"$SRC/systemd/l7cloud-build.timer" /etc/systemd/system/
systemctl daemon-reload
# first build before serving, then keep rebuilding every hour
sudo -u l7cloud python3 /opt/l7cloud/server/build_feeds.py --data /opt/l7cloud/data
systemctl enable --now l7cloud-feed.service l7cloud-build.timer
# an upgrade must not leave the old code running
systemctl restart l7cloud-feed.service
echo "l7cloud installed: http://$(hostname -I | awk '{print $1}'):8080/feeds/manifest.json"
