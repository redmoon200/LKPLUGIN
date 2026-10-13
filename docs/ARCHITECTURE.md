# Architecture

```
            +--------------------------- OPNsense 26.1 ----------------------------+
 clients -> | LAN/VLAN if -> BPF -> l7engine (libpcap, nDPI, SQLite) -> l7.db        |
            |                          |  \__ pf ioctl: tables l7_blk_<id>, kill states
            |   GUI (MVC) <-> API <-> configd <-> stats.py (read-only SQLite)         |
            |   apply.php: model -> engine.conf, policies.conf, unbound filter, pf    |
            |   Unbound + generated include (views per source network)                |
            +-----------------------------------------------------------------------+
                                   ^ feed-update (HTTP)
                            l7-cloud: build_feeds.py + feedserver.py
```

## Components

| Component | Path | Role |
|---|---|---|
| Engine | `engine/` | C daemon. Captures with libpcap on the monitored interfaces, tracks flows in a hash table, classifies with nDPI, writes flows/events to SQLite (WAL), enforces block policies. |
| Plugin | `security/layer7security/` | opnsense/plugins layout: MVC model, API controllers, views, configd actions, rc.d script, firewall hook. |
| Cloud server | `cloud/` | Optional list service: builds category lists from public blocklists, serves them over HTTP to the plugin's DNS filter. |
| Lab | `lab/`, `tests/` | Proxmox lab scripts and the end-to-end test. |

## Data flow

1. **Model** (`Layer7Security.xml`) holds general settings, users and policies.
2. **Apply** (`apply.php`, via `configctl layer7security apply`) uses
   `PolicyCompiler` to resolve interfaces, users and sources into plain data,
   then writes `engine.conf`, `policies.conf` and the Unbound include, reloads
   pf (`filter reload`) and restarts the engine.
3. **pf hook** (`layer7security_firewall()`): for every block policy it declares
   the persistent table `l7_blk_<id>` and one `block in quick from <source> to
   <l7_blk_id>` rule per source network. The engine only fills the tables.
4. **Engine** matches each flow once nDPI has classified it, and each DNS
   answer for a queried name, against the policies in order (first match
   wins; `allow` stops evaluation).
5. **Dashboard** calls `stats.py` through configd; it opens the database
   read-only, so the GUI cannot disturb the engine.

## Enforcement details

- *Flow based*: after nDPI classifies a flow (usually on the TLS ClientHello) a
  matching block policy puts the server address into the policy table and kills
  the client's states to it (`DIOCRADDADDRS`, `DIOCKILLSTATES`, microseconds;
  `pfctl` is the fallback).
- *DNS learning*: when a client resolves a name that nDPI maps to a blocked
  application (or that matches a host pattern), every returned address goes
  into the table before the client connects; states that raced the answer are
  killed. This covers round-robin address sets.
- *DNS filtering*: category and custom domain lists become Unbound
  `local-zone`s. Policies with source networks get their own Unbound *view*
  (`access-control-view`), so groups can have different lists.
- *Schedules*: the engine only applies a policy inside its window and flushes
  its table when the window closes; DNS views are re-evaluated every minute by
  cron.
- *Table lifetime*: entries expire after `blockTtl`; tables are flushed when
  the engine stops or policies reload.
- DNS flows are never matched by flow policies (blocking the resolver would cut
  the client off); unusable addresses (loopback, link-local, unspecified) are
  never added.

## Security notes

- The engine runs as root (BPF and pf need it) and drops nothing; its input is
  untrusted packets, so the parsers (`handle_l3`, `dns_name`, `dns_learn`)
  bound every read and never trust lengths. Fuzzing is part of the CI roadmap.
- No shell is used to run `pfctl`; arguments are addresses we formatted.
- API parameters are validated before they reach configd; the flow search
  phrase is reduced to a safe character set and bound by SQL parameters.
- All text from the network (host names, application names) is HTML-escaped in
  the GUI before it is displayed.
- Feed lists are validated line by line (domain syntax only) before use.

## Known limits

- IPv4 interface networks are resolved for interface/VLAN scopes; IPv6
  clients are covered when listed explicitly as sources or users.
- Encrypted traffic is classified by SNI/ALPN/handshake metadata and nDPI's
  heuristics; ECH or VPN traffic may show as TLS/VPN only. There is no TLS
  decryption.
- Blocking is per destination address; for shared CDN addresses the DNS name
  is the better handle (use host or DNS rules).
- One engine process captures all selected interfaces; for very high line
  rates switch the capture backend to netmap (planned behind `on_packet`).
