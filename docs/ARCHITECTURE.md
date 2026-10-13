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

## MAC binding

Bindings (name, MAC, optional IPv4, optional interface) are enforced in the
kernel with pf **ether rules**, which match the Ethernet source and the layer-3
address together. They cannot be emitted through the plugin API, so they live in
the anchor `l7sec_ether` that apply.php / the firewall hook load with
`pfctl -a l7sec_ether -f mac.rules`. The main ruleset only needs the line
`ether anchor "l7sec_ether"`, and it must come before scrub/NAT; the hook
emits it through a table declaration (printed before those sections). pf
evaluates ether rules "last match wins", so per interface the anchor holds:

1. strict mode: `block` all IPv4, pass DHCP discovery (`l3 from 0.0.0.0`)
2. strict mode: pass the MAC-only bindings
3. for each bound IP: `block` that IP from everyone ...
4. ... and `pass` it again from its own MAC

so a bound address can only be used by its MAC and, in strict mode, unknown
devices get no IPv4 at all. IPv4 only (EtherType 0x0800); ARP and IPv6 pass.
Optional static ARP entries (`arp -S`, tracked in `arp_static.json` so removed
bindings are cleaned up) stop forged ARP replies from re-pointing a bound IP.

The engine discovers devices from ARP and from IPv4 frames inside the monitored
networks (the firewall's own MACs are ignored), stores them in `devices`, and
raises `device-new` and `mac-spoof` events when a bound IP is used by another
MAC. The GUI lists discovered devices with a one-click *Bind*.

## GeoIP

`geo.py update` downloads the iptoasn.com country database (public domain, or any
mirror serving `ip2country-v{4,6}.tsv.gz`, such as the cloud server), normalises
it into `v4.tsv`/`v6.tsv`, and `geo.py build` turns each policy into a CIDR file
(countries minus exceptions; for *allow only*: countries plus private ranges plus
exceptions). Each policy is a persistent pf table `l7_geo_<id>` loaded from its
file, with labelled quick block rules at priority 1:

- *block*: `block in quick [on IF] from <table>` (inbound) and/or
  `block in quick on IF to <table>` (clients going out)
- *allow only*: the same with a negated table (`!<table>`)

If the database is missing, *allow only* rules are not emitted (fail open).
Rule label counters (`pfctl -s labels`) feed the "packets dropped" figures.
The engine loads the same ranges into memory and tags every flow with the
server's country (flows table, dashboard, flows page). Country data is an
approximation (registry allocation), so CDNs and VPNs can map elsewhere.

## AI services

nDPI 5.0 has no AI applications, so a catalog (`share/layer7security/ai_services.json`,
23 services, each with domain suffixes) is matched against the TLS and QUIC server
name and against DNS answers. The engine tags the flow (`flows.ai`), applies the
AI rules (allow, monitor, block) through the same pf tables as other policies, and
logs `ai-use` / `ai-block` events (at most one per client and service every five
minutes). Rules are compiled into ordinary policies placed before the user's own;
every service without a rule gets a catch-all with the default action.

QUIC hides the server name from the engine on later packets and bypasses any
proxy, so it can be dropped for the AI services (pf table `l7_ai_quic`) or for all
UDP/443 on the monitored interfaces. Clients then fall back to TCP, where the
engine and the inspection proxy can see them.

## AI content inspection

Only the AI services (or, for download protection, the sites) selected for
inspection are decrypted; every other connection is spliced untouched.

1. The engine puts the addresses of selected services into pf table `l7_ai_bump`
   when it sees a DNS answer or a first connection (that first, uninspected
   connection is killed so the client retries through the proxy).
2. pf redirects TCP/443 to those addresses to Squid on `127.0.0.1:3129`
   (transparent, `/dev/pf` gives the original destination).
3. Squid peeks at the SNI, bumps the selected names and splices everything else,
   issuing certificates from a **name-constrained CA** (X.509 NameConstraints:
   only the catalog's AI domains and the download sites chosen by the
   administrator; RSA 3072, two years). A stolen CA key cannot impersonate any
   other site. Apply refuses a site the CA is not allowed to sign for, and the CA
   can be replaced from the GUI (the clients must then install the new
   certificate).
4. Requests go through ICAP (`icap_server.py` on `127.0.0.1:1344`, `/dlp`
   REQMOD). The scanner (`dlp_rules.py`) finds payment cards (Luhn), identity
   numbers (SSN, Aadhaar with Verhoeff, PAN, IBAN, UK NINO), provider API keys,
   private key headers, JWTs, high-entropy secrets and source code. Per
   category: off, monitor (log) or block (403 with a JSON or HTML message).
   Multipart and binary uploads are not scanned. Squid and the scanner run
   under `rc.d/layer7security_proxy` (daemon(8) supervision); settings reach
   them as `/usr/local/etc/layer7security/inspection.json` (mode 0600) and a
   generated `squid.conf`.

Limits: certificate-pinned apps and ECH cannot be inspected; the CA must be
installed on the managed clients; time-of-day schedules on AI rules affect the
engine but not the Squid scope; streaming AI responses are never buffered.

## AI audit log

`audit.py` keeps `/var/db/layer7security/audit.db`: every record stores
SHA-256(previous hash + canonical record), so editing, deleting or reordering a
record breaks verification from that point. Appends are IMMEDIATE transactions so
the engine-event ingest job and the ICAP server share one chain. Content is masked
at the source (`****` keeping the last digits, API keys keep prefix and suffix;
source code is recorded only as line count and language) and masked again when
written. Records go to local syslog (`local5`) and optionally to a remote UDP
syslog target (RFC 5424); exports (CSV, JSON, JSONL) can be verified offline with
`audit.py verify-file`. Looking at the log, exporting, verifying, acknowledging
the privacy notice and changing audit settings are themselves recorded, and the
audit settings have their own privilege.

A hash chain only proves integrity against partial tampering: someone with root
can rewrite the whole file. The remote syslog target is the independent copy.

Privacy gate: audit and content inspection cannot be applied until the privacy
notice has been acknowledged (AI Audit > Privacy).

## Download protection

This is not a signature-based virus scanner and ships no signature engine.
`avscan.py` serves `/av` (RESPMOD) from the same ICAP server and decides on two
things only:

- **file type**, from the first bytes and the file name (not the server's
  claim): programs (PE, ELF, Mach-O), scripts, installer packages and archives;
  per type off, monitor or block;
- **SHA-256 reputation**: the downloaded file (transport compression removed) is
  looked up in a hash feed (downloaded on a schedule from an administrator-set
  URL; a failed or empty download keeps the previous list), the administrator's own
  list and the EICAR test file.

Plain HTTP is intercepted on `127.0.0.1:3128` (private destinations are never
redirected); HTTPS is only looked at for the sites listed by the administrator,
which are bumped like the AI services. Files larger than the configured limit are
not hashed (the type is still logged). Detections (time, client, site, file name
without query string, size, type, hash, action) are kept 90 days in `av.db`.

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
- The inspection CA key is `root:squid 0640`, the CA is name-constrained, the
  ICAP server listens on loopback only, and `inspection.json` is mode 0600.
- Raw request content is never stored: only masked snippets reach the audit log.

## Known limits

- IPv4 interface networks are resolved for interface/VLAN scopes; IPv6
  clients are covered when listed explicitly as sources or users.
- Encrypted traffic is classified by SNI/ALPN/handshake metadata and nDPI's
  heuristics; ECH or VPN traffic may show as TLS/VPN only. TLS is decrypted
  only for the AI services and download sites an administrator selects (see
  AI content inspection); everything else is never decrypted.
- Blocking is per destination address; for shared CDN addresses the DNS name
  is the better handle (use host or DNS rules).
- One engine process captures all selected interfaces; for very high line
  rates switch the capture backend to netmap (planned behind `on_packet`).
