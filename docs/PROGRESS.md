# Progress

## Phases
- [x] Foundation: repo files, reference clones
- [x] Lab VMs 9101-9103 created, OPNsense updated to 26.1.11_10
- [x] Engine language decision: C (see docs/ENGINE-COMPARISON.md)
- [ ] P1 Scaffold (GUI, API, configd, rc.d)
- [~] P2 Engine to SQLite: engine builds and classifies on the lab firewall (see below)
- [ ] P3 Dashboard
- [ ] P4 Blocking + DNS filtering
- [ ] P5 Policies
- [ ] P6 Hardening / packaging / CI / release

## Reference checkouts
- opnsense/plugins `stable/26.1` @ 6f3937f
- opnsense/core `26.1.9` @ b11d6b3 (lab firewall is 26.1.11_10; no API differences relied on)

## Lab (Proxmox 192.168.1.60)
| VMID | Name | Role | Addr |
|---|---|---|---|
| 9101 | opn-l7-fw | OPNsense 26.1.11_10, WAN vtnet1 (vmbr0, DHCP, 192.168.1.12), LAN vtnet0 10.77.0.1/24 | mgmt over WAN SSH |
| 9102 | l7-client | Ubuntu 24.04, test NIC ens4 10.77.0.2/24 behind OPNsense, mgmt eth0 192.168.1.72 (IPv6 disabled on eth0) | |
| 9103 | l7-cloud | Ubuntu 24.04 cloud-style management server | 192.168.1.73 |

The OPNsense LAN is a private UDP-socket NIC between 9101 and 9102 (`args:` in
each VM config); no bridge or network setting on the Proxmox host was changed.
Management SSH to OPNsense is allowed on WAN from 192.168.1.0/24 only (lab rule).
Verified OPNsense SSH host key against the console banner before trusting it.

## qm / Proxmox command log (2026-10-13)
| Command | Reason |
|---|---|
| `qm list`, `pvesm status`, `qm config 9001` (read-only) | inventory, pick free IDs |
| curl/bunzip2 images into `/var/tmp/lk-lab` | OPNsense 26.1.2 serial img, Ubuntu noble cloud img |
| `qm create 9101/9102/9103`, `qm set` (args, scsi0, ide2 cloudinit, ciuser, ipconfig, sshkeys), `qm importdisk`, `qm resize` | `lab/create-lab.sh` |
| `qm snapshot 9101/9102/9103 phase1-before` | before phase 1 |
| `qm start 9101/9102/9103` | boot |
| `qm stop 9101`, `qm destroy 9101 --purge` | rollback, see below |
| `qm create 9101` (nano image), `qm set`, `qm importdisk`, `qm resize 9101 scsi0 32G` (timed out: snapshot present) | rebuild |
| `qm stop 9101`, `qm delsnapshot 9101 phase1-before`, `qm resize 9101 scsi0 32G`, `qm snapshot 9101 phase1-before`, `qm start 9101` | resize cannot grow a qcow2 with an internal snapshot |
| `qm resize 9102 scsi0 16G`, `qm resize 9103 scsi0 20G` | resize timed out the first time, repeated |
| `qm monitor 9101` screendump, QMP `sendkey` via `/var/tmp/lk-lab/type.py` | drive the VGA console during first configuration |

## Rollbacks
- **9101 rebuilt.** Cause: I imported the OPNsense `serial` image, which is install
  media that runs in live mode (config not persistent). Destroyed and recreated
  from the pre-installed `nano` image. Only VM 9101 and files under
  `/var/tmp/lk-lab` were affected.
- The nano image's default LAN 192.168.1.1/24 overlaps the WAN subnet and broke
  routing; LAN moved to 10.77.0.1/24.
- Client mgmt NIC picked up IPv6 from the home router and bypassed the firewall
  in tests; IPv6 disabled on that NIC only.

## P2 evidence (engine on 9101, 2026-10-13)
- `l7engine --version` 0.1.0, `--list-apps` 467 apps, `--list-categories` 95.
- Live capture on LAN vtnet0, 0 packet drops. Classified YouTube, Facebook,
  NetFlix, Github, Reddit, Google, Cloudflare, Wikipedia, DNS, HTTP, NTP; flows
  and DNS query names stored in SQLite (WAL).
