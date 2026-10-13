# CLAUDE.md - os-layer7security (LKPLUGIN)

## Goal
Build `os-layer7security`, an open-source Layer-7 visibility and policy plugin
for OPNsense 26.x, similar in concept to commercial products but written from
scratch. Never copy third-party product code, assets or branding.

Non-goals: cloud-dependent licensing, closed-source components, TLS decryption.

## Environment
- Target: OPNsense **26.1.x** (FreeBSD 14.3 base). Lab firewall runs 26.1.11_10
  (installed from the 26.1.2 image, then updated). A `stable/26.7` branch exists
  upstream; port after 26.1 is released as v0.1.0.
- Reference sources (read-only, outside this repo, never committed):
  - `../reference/plugins` = opnsense/plugins branch `stable/26.1` @ 6f3937f
  - `../reference/core`    = opnsense/core tag `26.1.9` @ b11d6b3
- Proxmox lab host: `192.168.1.60` (root, SSH key only). Secrets live in
  `~/.lk-secrets/` (`.env`, key, `opn_api.json`), outside the repo. Never print
  or commit them. The lab scripts read them from there.
- Lab VMs (the only things this project may touch on the host):

| VMID | Name       | Role                                    | Addr                     | Status  |
|------|------------|-----------------------------------------|--------------------------|---------|
| 9101 | opn-l7-fw  | OPNsense 26.1.11 firewall, plugin under test | WAN vtnet1 192.168.1.12 (DHCP), LAN vtnet0 10.77.0.1/24 | running |
| 9102 | l7-client  | Ubuntu 24.04 client behind OPNsense LAN | mgmt 192.168.1.72, LAN 10.77.0.2 | running |
| 9103 | l7-cloud   | Ubuntu 24.04 cloud-style feed server (`cloud/`) | 192.168.1.73, :8080 | running |

  The OPNsense LAN is a private UDP socket NIC between 9101 and 9102 defined in
  each VM's `args:`, so no host bridge or network config is changed.
  OPNsense is managed over its WAN address (lab rule allows 22/443 from
  192.168.1.0/24); its root shell is csh, so remote scripts go through `sh -s`.
- Existing VMs 100-111 and 9001 belong to the user: never touch them.

## Layout
```
security/layer7security/      plugin, opnsense/plugins layout
  Makefile  pkg-descr
  src/etc/inc/plugins.inc.d/layer7security.inc   services, pf hook, cron
  src/etc/rc.d/layer7security                    daemon(8) supervised engine
  src/opnsense/mvc/app/{controllers,models,views,library}/OPNsense/Layer7Security/
  src/opnsense/service/conf/actions.d/actions_layer7security.conf
  src/opnsense/scripts/OPNsense/Layer7Security/  apply.php stats.py feed_update.py geo.py catalog.sh
  src/share/layer7security/seeds/                small DNS category seed lists
engine/                       l7engine (C): libpcap + nDPI + SQLite + pf ioctl, geo.c, dev.c
cloud/                        feed builder/server for the DNS filter lists
lab/                          Proxmox + deploy scripts
tests/e2e.sh                  end-to-end test over the REST API
docs/                         ARCHITECTURE, USER-GUIDE, ENGINE-COMPARISON, PROGRESS
```

## Build / deploy / test commands
- Deploy engine + plugin to the lab firewall: `lab/deploy-plugin.sh`
  (builds `engine/` on the VM, installs to `/usr/local`, restarts configd and
  php_fpm). Engine only: `lab/deploy-engine.sh`.
- Engine on the VM: `make -C /root/engine`; robustness test `make -C /root/engine check`
  (ASan/UBSan fuzz of the packet parsers).
- Apply config from the shell: `configctl layer7security apply`; service:
  `configctl layer7security start|stop|restart|status`.
- API check (lab): `. lab/env.sh; api GET /api/layer7security/service/status`.
- pf check: `pfctl -t l7_blk_1 -T show`, `pfctl -sr | grep l7_blk`.
- End-to-end: `sh tests/e2e.sh` (50 checks; needs lab/env.sh, API key, client VM with a
  VLAN, internet). MAC tests use `lab/spoof.sh` (network namespace with a chosen MAC/IP).
- Lint: `php -l`, `python3 -m py_compile`, `xmllint --noout`, `shellcheck -S warning -s sh`
  (CI runs these plus a FreeBSD build of the engine).
- Package on the firewall: `lab/build-package.sh` (see docs/PROGRESS.md for the
  result).

## Coding rules
- Match `opnsense/plugins` conventions (MVC, models in XML, configd actions).
- BSD-2-Clause header in every source file. No third-party code copied in.
- No secrets in the repo; `.gitignore` excludes keys, `.env`, tokens. CI greps for them.
- Escape everything that comes from the network before putting it in the GUI.
- Never call a shell with data we did not format ourselves; `pfctl` is `execv`'d
  and the hot path uses pf ioctls.
- Windows hosts: keep LF line endings (`.gitattributes`); beware CRLF from
  Windows Python in shell loops (`tr -d '\015'`).
- Snapshot before each phase: `qm snapshot <id> phaseN-before`; log every `qm`
  command and every rollback (with cause) in `docs/PROGRESS.md`.

## Roadmap and status
- P1 Scaffold: GUI, API, configd, rc.d - done
- P2 nDPI engine to SQLite (C chosen, see docs/ENGINE-COMPARISON.md) - done
- P3 Dashboard - done
- P4 Blocking via pf tables + DNS filtering (+ DNS-learned blocking) - done
- P5 Per-VLAN / user / scheduled policies - done (VLAN test: see PROGRESS)
- P6 Hardening, packaging, CI, release - done for 0.1.0 and 0.2.0, see PROGRESS
- v0.2.0 adds MAC binding (pf ether rules in anchor l7sec_ether, strict mode, device
  discovery, spoof events, static ARP) and GeoIP filtering (geo.py database + per-policy
  pf tables, country tags on flows)
