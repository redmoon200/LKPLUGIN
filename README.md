# os-layer7security

An open-source **Layer 7 (application-aware) firewall plugin for OPNsense 26.1**.
It identifies the applications and categories behind your traffic with
[nDPI](https://www.ntop.org/products/deep-packet-inspection/ndpi/), stores flows
in a local SQLite database, shows them on a dashboard, and enforces policies by
interface/VLAN, user and schedule through pf tables and Unbound DNS filtering.

Written from scratch. It is independent of, and not affiliated with, Zenarmor /
Sunny Valley Networks or the OPNsense project / Deciso B.V.; it uses none of
their code, assets or branding. "OPNsense" is a trademark of Deciso B.V.

## Features

- **Visibility**: per-flow application, category, host name (TLS SNI, HTTP, DNS),
  bytes and packets; dashboard with traffic over time, top applications,
  categories, clients and policy blocks; searchable flow table.
- **Policies** (first match wins; *monitor*, *allow* exemption, *block*):
  match on application, nDPI category or host name; scope by interface/VLAN,
  source network or named user; active days and time window.
- **Blocking** without inline proxying: destination addresses go into per-policy
  pf tables with matching quick-block rules; matching states are killed through
  the pf ioctl interface. DNS answers for blocked applications pre-arm the block
  before the client connects.
- **DNS filtering**: category lists (ads, trackers, malware, phishing, adult,
  gambling, social, streaming, games) and custom domains in Unbound, with
  per-group views so different networks can have different lists. A small cloud
  feed server in `cloud/` builds the lists from public sources.
- Native OPNsense plugin: MVC GUI, REST API, configd actions, rc.d service.

## Status

v0.1.0, tested on the lab described in [docs/PROGRESS.md](docs/PROGRESS.md)
(OPNsense 26.1.11, end-to-end checks, fuzzed parsers, CI on GitHub). It is a
young project: read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for what it
does and does not do (no TLS decryption; blocking is per address and DNS name).

## Install

```sh
pkg add https://github.com/redmoon200/LKPLUGIN/releases/download/v0.1.0/os-layer7security-0.1.0.pkg
```

Then open **Services > Layer 7 Security** and follow
[docs/USER-GUIDE.md](docs/USER-GUIDE.md).

## Build and test

See [CLAUDE.md](CLAUDE.md) for the repository layout and every command. In
short: the engine is C (`engine/`, libpcap + nDPI + SQLite), the plugin follows
the `opnsense/plugins` layout (`security/layer7security/`), `lab/` holds the
Proxmox lab and deploy scripts, and `tests/` the end-to-end and GUI tests.

## nDPI licensing

nDPI is LGPL with some dual-licensed components. Since nDPI 6 the library asks
which license applies; this project defaults to the not-for-profit LGPL mode,
which suits open-source use. If you deploy it commercially, obtain a license
from ntop and rebuild with `-DL7_NDPI_LICENSE=<value>`.

## License

BSD 2-Clause. See [LICENSE](LICENSE).
