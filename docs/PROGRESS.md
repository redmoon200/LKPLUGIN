# Progress

## Phases
- [x] Foundation: repo files, reference clones
- [x] Lab VMs 9101-9103 created, OPNsense updated to 26.1.11_10
- [x] Engine language decision: C (docs/ENGINE-COMPARISON.md)
- [x] P1 Scaffold: MVC GUI, REST API, configd actions, rc.d service, pf hook
- [x] P2 Engine to SQLite: libpcap + nDPI + SQLite (WAL), flows and events
- [x] P3 Dashboard: summary tiles, timeline, top apps, categories, clients, blocks; flow search
- [x] P4 Blocking: pf tables + quick-block rules, direct pf ioctls, DNS-learned blocking, Unbound DNS filtering with a cloud feed server
- [x] P5 Policies: per interface/VLAN, source network, named user, schedule; allow/monitor/block with ordering
- [x] P6 Hardening, packaging, CI, release: sanitizer fuzzing, `.pkg` build and install test, GitHub Actions; release tag below

Development of P2-P5 happened in one continuous session, so only `phase1-before`
and `phase6-before` snapshots exist (no per-phase snapshot for P2-P5).

## Reference checkouts
- opnsense/plugins `stable/26.1` @ 6f3937f
- opnsense/core `26.1.9` @ b11d6b3 (lab firewall is 26.1.11_10; no API differences relied on)

## Lab (Proxmox 192.168.1.60)
| VMID | Name | Role | Addr |
|---|---|---|---|
| 9101 | opn-l7-fw | OPNsense 26.1.11_10, WAN vtnet1 (vmbr0, DHCP, 192.168.1.12), LAN vtnet0 10.77.0.1/24, VLAN 10 `vlan0.10` = opt1 10.88.0.1/24 | mgmt over WAN SSH |
| 9102 | l7-client | Ubuntu 24.04, test NIC ens4 10.77.0.2/24, VLAN `ens4.10` 10.88.0.2/24, mgmt eth0 192.168.1.72 (IPv6 disabled on eth0) | |
| 9103 | l7-cloud | Ubuntu 24.04, feed server on :8080 (`cloud/`) | 192.168.1.73 |

The OPNsense LAN is a private UDP-socket NIC between 9101 and 9102 (`args:` in
each VM config); no bridge or network setting on the Proxmox host was changed.
Management SSH to OPNsense is allowed on WAN from 192.168.1.0/24 only (lab rule).
The OPNsense SSH host key was verified against the console banner before it
was trusted.

## Test evidence (2026-10-13)
- **End-to-end** (`tests/e2e.sh`, 25 checks, REST API + traffic from the client):
  classification, block by application, by category for a named user, by host
  name, allow-before-block ordering, schedule inside/outside the window, per-VLAN
  scope with no double counting, global and per-group DNS filtering, cleanup.
  Repeated clean runs: 25/25, 25/25, 25/25 (final pass: see git log message of
  the release commit). Intermittent failures seen during development were
  traced to test bugs or to overlapping manual lab activity, not engine leaks.
- **GUI** (`tests/ui_check.py`, `tests/ui_crud.py`, `tests/ui_shots.py`): all six
  pages render, 0 JavaScript errors in a real Chromium, selectors are populated
  from the nDPI catalog (467 applications, 94 categories), create/delete through
  the dialogs works.
- **Fuzzing**: `engine/tests/fuzz.c` feeds mutated IPv4/IPv6/TCP/UDP/TLS/DNS
  packets to the real parsers under ASan + UBSan: 2.5 million packets on the lab
  (nDPI 5.0), 600k per CI run (nDPI 6.0); no findings.
- **Package**: `lab/build-package.sh` builds `os-layer7security-0.1.0.pkg`
  (~87 KB) with the opnsense/plugins framework. Installed on the firewall with
  all hand-deployed files removed first; the post-install hook builds the
  catalog and the engine runs from the packaged files. Upgrade (`pkg add -f`)
  and boot-start were verified.
- **CI** (GitHub Actions): lint job (PHP, Python, XML, shellcheck, secret scan,
  feed-parser self-test) and a FreeBSD 14.3 job that builds the engine against
  the repo's nDPI 6 and runs the fuzz check: green.

## v0.2.0: MAC binding and GeoIP (2026-10-13)
- **MAC binding**: pf ether rules in anchor `l7sec_ether` (the ruleset reference is
  emitted through a table declaration, the only hook that lands before scrub/NAT).
  Verified in the lab: right MAC works, wrong MAC on a bound IP is dropped, an
  unbound IP is untouched in *protect*, an unknown device is dropped in *strict*,
  a MAC-only binding lets a device on but cannot take over a bound IP, static ARP
  entries are created and removed with the binding, mode *off* empties the anchor.
  The engine discovers devices (ARP + IPv4 inside monitored networks), classifies
  them bound / spoof / unbound and raises `mac-spoof` events; the GUI binds a
  discovered device with one click.
- **GeoIP**: iptoasn.com database (457k IPv4 / 120k IPv6 ranges, 14 s to build; also
  served by the cloud mirror) turned into per-policy pf tables. Verified: block
  Germany outbound (14,354 prefixes) drops German hosts only; allow-only France
  with an exception passes France and the excepted host, drops Germany and the US,
  keeps DNS/firewall reachable (private ranges); rule counters report drops; flows
  and the dashboard carry the server country.
- **Tests**: e2e grew from 25 to 50 checks; `tests/ui_crud2.py` covers the new
  dialogs (GeoIP policy, binding, invalid MAC rejected, one-click Bind); fuzz now
  also feeds mutated Ethernet/ARP/VLAN frames through `on_packet`
  (2 million frames on the lab, clean).
- **Package**: `os-layer7security-0.2.0.pkg`, installed over 0.1.0 (upgrade) and
  again after wiping every plugin file (package-only). On that install the full
  suite passed 50/50 in two consecutive runs, plus the render, dialog and fuzz tests.

## Bugs found and fixed while testing
- Host-matching policies matched the DNS flow itself and put the resolver in the
  block table (cut DNS). DNS flows are no longer policy targets.
- First connection to a not-yet-learned address could slip through (pfctl fork
  latency). Fixed with direct `DIOCRADDADDRS`/`DIOCKILLSTATES`, plus DNS-learned
  pre-blocking and killing states that raced the answer.
- nDPI 6 changed `ndpi_init_detection_module()`; the engine builds against 5 and 6.
- Tagged frames were counted twice when a trunk and its VLAN were both monitored.
- Late server packets after a state kill created reversed (server as client)
  flows; bare RSTs no longer start flows and the server side is detected.
- OPNsense `serial` image is install media (live mode); the `nano` image is the
  persistent one. Default LAN 192.168.1.1/24 collided with the WAN subnet.
- tar extraction as root kept Windows UIDs (`--no-same-owner` now used).

## qm / Proxmox command log (2026-10-13)
| Command | Reason |
|---|---|
| `qm list`, `pvesm status`, `qm config 9001` (read-only) | inventory, pick free IDs |
| curl/bunzip2 images into `/var/tmp/lk-lab` | OPNsense 26.1.2 serial + nano images, Ubuntu noble cloud image |
| `qm create 9101/9102/9103`, `qm set` (args, scsi0, ide2 cloudinit, ciuser, ipconfig, sshkeys), `qm importdisk`, `qm resize` | `lab/create-lab.sh` |
| `qm snapshot 9101/9102/9103 phase1-before` | before phase 1 |
| `qm start 9101/9102/9103` | boot |
| `qm stop 9101`, `qm destroy 9101 --purge` | rollback, see below |
| `qm create 9101` (nano image), `qm set`, `qm importdisk`, `qm resize 9101 scsi0 32G` (timed out: snapshot present) | rebuild |
| `qm stop 9101`, `qm delsnapshot 9101 phase1-before`, `qm resize 9101 scsi0 32G`, `qm snapshot 9101 phase1-before`, `qm start 9101` | resize cannot grow a qcow2 with an internal snapshot |
| `qm resize 9102 scsi0 16G`, `qm resize 9103 scsi0 20G` | resize timed out the first time, repeated |
| `qm monitor 9101` screendump, QMP `sendkey` via `/var/tmp/lk-lab/type.py` | drive the VGA console during first configuration |
| `qm snapshot 9101 phase6-before`, `qm snapshot 9102 phase6-before` | before phase 6 |

No new `qm` commands were needed for 0.2.0 (no VM was created, resized or snapshotted).

## Rollbacks
- **9101 rebuilt.** Cause: I imported the OPNsense `serial` image, which is install
  media that runs in live mode (config not persistent). Destroyed and recreated
  from the pre-installed `nano` image. Only VM 9101 and files under
  `/var/tmp/lk-lab` were affected.
- The nano image's default LAN 192.168.1.1/24 overlaps the WAN subnet and broke
  routing; LAN moved to 10.77.0.1/24.
- Client mgmt NIC picked up IPv6 from the home router and bypassed the firewall
  in tests; IPv6 disabled on that NIC only.
- Stray Windows UIDs on `/usr/local` directories after a tar extraction as root;
  chowned back to root:wheel, deploy script fixed.

## Known limits and open items
- Per-VLAN/interface scopes resolve IPv4 networks; IPv6 clients must be listed
  as sources or users.
- Users are identified by static IP addresses only (no directory/captive-portal
  integration).
- No TLS decryption; encrypted traffic is classified from handshake metadata
  (ECH/VPN traffic may show as TLS/VPN). Blocking is per address and DNS name.
- Capture is libpcap/BPF; netmap for very high line rates is a documented option.
- MAC binding covers IPv4 only (ARP and IPv6 are not filtered by the ether rules).
- GeoIP data is registry based; CDN and VPN addresses can map to another country.
- Not yet done: OPNsense 26.7 port, libFuzzer corpus in CI, dashboard widget for
  the OPNsense lobby, signed package repository (the `.pkg` is installed with
  `pkg add`), Zenarmor-style reports/exports.
- Commercial use of nDPI 6 needs a license from ntop (see README).
