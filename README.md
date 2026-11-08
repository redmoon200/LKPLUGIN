# os-layer7security

An open-source **Layer 7 (application-aware) security console for OPNsense 26.1**.
It identifies the applications and websites behind your traffic with
[nDPI](https://www.ntop.org/products/deep-packet-inspection/ndpi/), shows what is
happening live, and lets IT support staff allow or block websites, IP addresses,
applications, categories and AI services in a few clicks.

Written from scratch. It is independent of, and not affiliated with, Zenarmor /
Sunny Valley Networks or the OPNsense project / Deciso B.V.; it uses none of
their code, assets or branding. "OPNsense" is a trademark of Deciso B.V.

## The console

Three menus appear in the OPNsense sidebar:

| Menu | Pages |
|------|-------|
| **Layer 7** | Overview (protection status, traffic), **Live Sessions**, Users and Access (named users, sign-in), MAC Binding, GeoIP, Settings |
| **Protection** | **Web Control**, **Application Control**, **CFS** (content filtering), **DPI-SSL**, Antivirus |
| **AI** | **AI Service**, **AI Inspection**, **AI Audit** |

Every module has the same layout: a header with its on/off state and an Apply
button, status tiles, and tabs (overview, rules or settings, activity log).

## Features

- **Live Sessions**: every open connection with device, website or address, port,
  application, country, download and upload rate, age and decision; by device and
  by website; what was just blocked; search and history. **Block** or **Allow** a
  website, a whole domain (`*.example.com`) or an IP address straight from the
  list: one confirmation, for everybody or one device, for good or for a time,
  active within seconds, open connections are cut.
- **Web Control**: allow and block lists of websites and IP addresses with
  wildcards (`*instagram.com`, `*.example.com`, `ads*.example.net`), per device,
  temporary rules, a "what happens to this site" test box and an activity list.
- **Application Control**: one-click Allow / Watch / Block per category
  (social, streaming, games, VPN, P2P ...) and per application (467 known by
  nDPI), plus full rules by interface/VLAN, device, user and schedule.
- **CFS (content filtering)**: website categories (ads, trackers, malware,
  phishing, botnets, adult, gambling, social, streaming, games) enforced in
  Unbound, group rules, forced safe search and YouTube restricted mode, known-bad
  IP lists (botnet C2, compromised hosts, attackers, hijacked networks, Tor),
  category lookup.
- **DPI-SSL**: TLS decryption through Squid SSL-bump, either for the sites you
  list (name-constrained CA) or for all HTTPS except an exclusion list (full CA),
  with ready-made exclusions for pinned apps and a session log.
- **Antivirus for downloads**: file-type control from content, MD5 / SHA-1 /
  SHA-256 reputation (cloud lists, own list, EICAR), **YARA virus signatures**,
  detection log and a "scan a file" test tool. Not a replacement for endpoint
  antivirus.
- **Users and Access**: devices can be required to **sign in** on a login page
  (OPNsense users, LDAP or RADIUS) before they can use the web; policies then
  follow the signed-in user. Named users and devices for rules.
- **AI Service / Inspection / Audit**: identifies 23 AI services (ChatGPT, Claude,
  Gemini, Copilot ...), allow / watch / block each, optional data-loss checks
  (cards, ID numbers, API keys, source code) and a tamper-evident audit log with
  masked excerpts, export and syslog.
- **MAC binding**, **GeoIP filtering**, per-interface/VLAN policies, schedules.
- **Feed server (separate product, not in this repository)**: the plugin downloads website categories, IP threat lists, malware hashes and
  YARA rules from a feed server that you or your vendor run. Enter its address under **Layer 7 > License**.
- **License module**: trial, yearly and lifetime keys; see [docs/LICENSING.md](docs/LICENSING.md).
- **Monitoring** (plugin side): once a minute the plugin can report health, gateways, the internet line and counters of blocked traffic to the vendor's
  server. No browsing history, client names or user names are sent; the customer can switch it off.
- **Remote support** (plugin side): off by default; the customer chooses *view only* or *full support*. Commands are signed by the vendor, valid for ten
  minutes, run from a fixed list, and written to a log the customer can read.
- **Updates**: signed plugin releases from the vendor's server, installed with one button (or automatically) with an automatic rollback if the new
  version does not start; the License page also shows OPNsense firmware and patch updates that are waiting.
- Native OPNsense plugin: MVC GUI, REST API, configd actions, rc.d services.

## Status

v0.6.0, tested on the lab described in [docs/PROGRESS.md](docs/PROGRESS.md)
(OPNsense 26.1.11, end-to-end checks, browser tests, fuzzed parsers, CI on
GitHub). It is a young project: read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
for what it does and does not do (TLS is decrypted only where you ask for it;
blocking is per address and DNS or TLS name).

## Install

The package depends on `ndpi`, `sqlite3`, `squid` and `yara`. On a fresh firewall install them first, otherwise `pkg add` stops with
"Missing dependency":

```sh
pkg update
pkg install -y ndpi sqlite3 squid yara
pkg add https://github.com/redmoon200/LKPLUGIN/releases/download/v0.6.0/os-layer7security-0.6.0.pkg
```

Then open the **Layer 7** menu and follow [docs/USER-GUIDE.md](docs/USER-GUIDE.md). To get the category lists, bad-address lists, malware hashes
and signatures, enter the address of your feed server under **Layer 7 > License**, where you also enter a license key (or start the 30-day trial
if your server offers it).

## Build and test

See [CLAUDE.md](CLAUDE.md) for the repository layout and every command. In
short: the engine is C (`engine/`, libpcap + nDPI + SQLite), the plugin follows
the `opnsense/plugins` layout (`security/layer7security/`), `lab/` holds the Proxmox lab and deploy scripts, and `tests/` the
end-to-end, unit and browser tests.

## nDPI licensing

nDPI is LGPL with some dual-licensed components. Since nDPI 6 the library asks
which license applies; this project defaults to the not-for-profit LGPL mode,
which suits open-source use. If you deploy it commercially, obtain a license
from ntop and rebuild with `-DL7_NDPI_LICENSE=<value>`.

## License

BSD 2-Clause. See [LICENSE](LICENSE).
