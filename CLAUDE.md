# CLAUDE.md - os-layer7security (LKPLUGIN)

## Goal
Build `os-layer7security`, an open-source Layer-7 visibility and policy plugin
for OPNsense 26.x, similar in concept to commercial products but written from
scratch. Never copy third-party product code, assets or branding.

Non-goals: cloud-dependent licensing, closed-source components, TLS decryption.

## Environment
- Target: OPNsense **26.1.x** (FreeBSD 14.x base). Lab image 26.1.2, updated to
  latest 26.1.x. The 26.7 branch exists; port after 26.1 works.
- Reference sources (read-only, outside this repo, never committed):
  - `../reference/plugins` = opnsense/plugins branch `stable/26.1` @ 6f3937f
  - `../reference/core`    = opnsense/core tag `26.1.9` @ b11d6b3
- Proxmox lab host: `192.168.1.60` (root, SSH key only). Secrets live in
  `~/.lk-secrets/.env`, outside the repo. Never print or commit them.
- Lab VMs (the only things this project may touch on the host):

| VMID | Name       | Role                                    | Addr                     | Status  |
|------|------------|-----------------------------------------|--------------------------|---------|
| 9101 | opn-l7-fw  | OPNsense 26.1 firewall, plugin under test | WAN 192.168.1.71 (vmbr0) | planned |
| 9102 | l7-client  | Ubuntu 24.04 client behind OPNsense LAN | mgmt 192.168.1.72        | planned |
| 9103 | l7-cloud   | Ubuntu 24.04 cloud-style management srv | 192.168.1.73             | planned |

  The OPNsense LAN is a private UDP socket NIC between 9101 and 9102 defined in
  each VM's `args:`, so no host bridge or network config is changed.
- Existing VMs 100-111 and 9001 belong to the user: never touch them.

## Layout
```
security/layer7security/      plugin, opnsense/plugins layout
  Makefile  pkg-descr
  src/etc/inc/plugins.inc.d/  service + firewall hooks
  src/opnsense/mvc/app/{controllers,models,views}/OPNsense/Layer7Security/
  src/opnsense/service/conf/actions.d/   configd actions
  src/opnsense/scripts/OPNsense/Layer7Security/
  src/etc/rc.d/               rc.d service script
engine/                       packet engine (libpcap + nDPI + SQLite)
lab/                          Proxmox lab scripts
docs/                         PROGRESS.md, design notes
```

## Build / deploy / test (filled in as phases land)
- Build package on the firewall VM: `make -C security/layer7security package`
- Install: `pkg add work/pkg/os-layer7security-*.pkg`
- Reload: `configctl layer7security reconfigure`, `service configd restart`
- API check: `curl -k -u KEY:SECRET https://FW/api/layer7security/service/status`
- pf check: `pfctl -t layer7_block -T show`
- Lint: `php -l`, `python3 -m py_compile`, `make -C ... lint`

## Coding rules
- Match `opnsense/plugins` conventions (MVC, models in XML, configd actions).
- BSD-2-Clause header in every source file. No third-party code copied in.
- No secrets in the repo; `.gitignore` excludes keys, `.env`, tokens.
- Snapshot before each phase: `qm snapshot <id> phaseN-before`; log every `qm`
  command and every rollback (with cause) in `docs/PROGRESS.md`.

## Roadmap
- P1 Scaffold: GUI, API, configd, rc.d
- P2 nDPI engine to SQLite
- P3 Dashboard
- P4 Blocking via pf tables + DNS filtering
- P5 Per-VLAN / user / scheduled policies
- P6 Hardening, packaging, CI, release
