# Progress

## Phases
- [x] Foundation: repo files, reference clones
- [ ] Lab VMs 9101-9103 (blocked, see log)
- [ ] Engine language decision (docs/ENGINE-COMPARISON.md)
- [ ] P1 Scaffold
- [ ] P2 Engine to SQLite
- [ ] P3 Dashboard
- [ ] P4 Blocking + DNS filtering
- [ ] P5 Policies
- [ ] P6 Hardening / packaging / CI / release

## Reference checkouts
- opnsense/plugins `stable/26.1` @ 6f3937f
- opnsense/core `26.1.9` @ b11d6b3

## qm / Proxmox command log
| Time (2026-10-13) | Command | Reason |
|---|---|---|
| ~08:55 | read-only: `qm list`, `pvesm status`, `qm config 9001` | inventory, pick free IDs |
| ~08:56 | downloaded OPNsense 26.1.2 serial img + Ubuntu noble cloud img to `/var/tmp/lk-lab` on host | VM disk sources |
| - | `qm create 9101-9103` (script not yet in repo) | NOT RUN: blocked by the Claude Code auto-mode classifier, awaiting user decision |

## Rollbacks
None.
