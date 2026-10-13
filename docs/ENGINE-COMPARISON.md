# Engine language: Rust vs Go vs C

Decision: **C** (implemented, see `engine/`). The engine does packet capture
(libpcap, netmap later), nDPI classification, SQLite writes and pf control on
FreeBSD/OPNsense 26.1.

| Criterion | C | Rust | Go |
|---|---|---|---|
| nDPI binding | native, headers used directly; same ABI as the `ndpi` pkg | needs bindgen/FFI wrapper over ~100 functions and large structs (`ndpi_flow_struct` is read directly for `host_server_name`) | cgo; per-packet cgo call overhead (~50-100 ns) and pinned-memory rules |
| libpcap / netmap | direct; `pcap_set_immediate_mode`, BPF fds work with `poll()` | `pcap` crate OK; netmap needs own FFI | `gopacket` pulls cgo anyway |
| FreeBSD 14 / OPNsense support | clang and libpcap are in base, no extra toolchain | Rust toolchain is not in OPNsense base; cross build or ports needed; static musl-free binary fine | Go runs on FreeBSD but adds a 10+ MB runtime and GC pauses in the capture path |
| Performance | no allocator or GC surprises; flow table is a plain hash | comparable to C, bounds checks are cheap here | GC and cgo copies cost throughput on a small firewall CPU |
| Memory safety | manual; mitigated by bounded parsers, `-Wall -Wextra`, ASan builds | strongest | strong (outside cgo) |
| Packaging in the plugin flow | tiny binary built on the firewall or in the package stage, deps are only `ndpi` and `sqlite3` | extra build dependency in CI and on devs' machines | extra runtime/toolchain dependency |
| Contributor pool for OPNsense/FreeBSD | largest (base system, nDPI, ntopng are C) | growing | large but rarely on firewall data paths |

## Why C
- nDPI is a C library and its flow struct is part of the public header; any other
  language adds a binding layer around the hottest call (one nDPI call per
  packet) with no benefit for a single-purpose daemon.
- Everything needed is already on a stock OPNsense: clang, libpcap headers, and
  the `ndpi`/`sqlite3` packages from the official repo.
- The unsafe surface is small and contained: one packet parser (`handle_l3`),
  fixed-size buffers with `snprintf`, no shell (pfctl is run with `execv`).

## Risks and mitigations
- Parser bugs: fuzz `handle_l3` with libFuzzer/AFL in CI (P6); run with
  `-fsanitize=address,undefined` in tests.
- High line rates: libpcap/BPF is fine for the lab and small sites; for 10 GbE
  switch the capture backend to netmap behind the same `on_packet` interface
  (P6 option).
- If a Rust rewrite is ever wanted, the SQLite schema, `engine.conf` and
  `policies.conf` formats are the stable interfaces.
