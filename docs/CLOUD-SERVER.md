# Cloud feed server

One small server collects public security data and serves it to your firewalls.
The firewalls never talk to the original sources, so you control what they get.

## Install

On a Debian or Ubuntu machine (the lab uses VM 9103):

```sh
sudo sh cloud/install.sh
```

It creates the user `l7cloud`, installs `yara` (only used to test that every
signature file compiles), copies the scripts to `/opt/l7cloud`, builds the first
set of lists into `/var/lib/l7cloud/feeds` and starts

- `l7cloud-feed.service`: the HTTP server on port 8080 (read only, whitelisted names),
- `l7cloud-build.timer`: rebuilds everything every hour.

Then enter `http://<server>:8080/feeds` on the firewall under
**Protection > CFS > Settings > Cloud server address**.

## What it serves

| Path | Content | Used by |
|------|---------|---------|
| `/feeds/<category>.txt` | domains per website category (ads, trackers, malware, phishing, adult, gambling, social, botnet, ...) | CFS categories |
| `/feeds/ip/<list>.txt` | public IPv4 addresses and networks: `c2`, `compromised`, `attackers`, `drop`, `tor` | CFS known-bad addresses |
| `/feeds/hashes/<algo>.txt` | `sha256`, `sha1`, `md5` malware hashes, `hash` or `hash;family` per line | Antivirus |
| `/feeds/yara/index.json`, `/feeds/yara/<file>.yar` | signature files with SHA-256 checksums | Antivirus signatures |
| `/feeds/manifest.json` | what was built, how many entries, sources and licences | status pages |
| `/feeds/ip2country-v4.tsv.gz`, `-v6` | country database mirror | GeoIP |
| `/health` | liveness | monitoring |

ETag and gzip are supported. Private and special addresses are never published
in IP lists, so a list cannot cut off a network by mistake.

## Sources

| Data | Source | Terms |
|------|--------|-------|
| domains | StevenBlack hosts, anudeepND adservers, Phishing.Database | MIT |
| malware, botnet domains and hashes, C2 addresses | abuse.ch URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker | CC0 |
| compromised, attacker addresses | Emerging Threats, CINS Army, blocklist.de | free to use |
| hijacked networks | Spamhaus DROP | free for non-commercial use: check before commercial use |
| Tor exits | Tor Project bulk exit list | public |
| MD5 hashes | VirusShare (the newest three lists by default, `--virusshare N`) | free to use |
| signatures | the project's own rules (`cloud/data/yara/`), ReversingLabs open source YARA rules (`--no-community-yara` to leave them out) | BSD-2-Clause, MIT |

A source that cannot be reached never empties an existing list; the manifest
records the error and the previous file stays.

## Operating

- Rebuild now: `sudo -u l7cloud python3 /opt/l7cloud/server/build_feeds.py --data /opt/l7cloud/data`
  (`--only domains,ips,hashes,yara,geoip` for parts).
- Add your own signatures: put `.yar` files into `cloud/data/yara/`, run
  `install.sh` again. Files that do not compile are left out and listed in
  `manifest.json` under `yara.rejected`.
- Add your own domain lists: `cloud/data/<category>.txt`.
- The firewall refreshes domains every 6 hours, bad addresses and hashes every
  3 hours and signatures every 12 hours, or on demand from the CFS and Antivirus pages.
