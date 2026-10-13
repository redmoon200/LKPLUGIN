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
   login portal (portal.py, :8444 + :8081) <-> auth.py <-> pf <l7_auth_ok>, sessions.tsv
   Squid SSL-bump + ICAP (icap_server.py: DLP, avscan.py hashes + YARA)
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

## Console layout

`Menu.xml` creates three top-level menus: **Layer 7** (overview, live sessions,
users and access, MAC binding, GeoIP, settings), **Protection** (Web Control,
Application Control, CFS, DPI-SSL, Antivirus) and **AI** (AI Service, AI
Inspection, AI Audit). All pages share `www/css/layer7security/console.css`,
`www/js/layer7security/console.js` (helpers: `L7.api`, tiles, pills, dialogs,
`L7.applyButton`) and `views/.../partials/header.volt` (title, module state,
engine state, Apply). The old addresses (`policies`, `dns`, `flows`, `users`)
redirect to the new pages. Pages talk to small API controllers
(`webcontrol`, `live`, `appcontrol`, `cfs`, `access`, `ai`, ...) and the generic
settings API.

## Web Control

Rules live in the model (`webcontrol.rule`: kind domain or ip, value, allow or
block, optional sources, optional end time). `PolicyCompiler` turns them into

- engine policies (`Web Control: allow` first, then `Web Control: block` per
  source scope, 100 patterns per policy) placed before everything else, so an
  allow beats every other rule;
- Unbound zones: a pattern `*.x`, `*x` or `x` becomes the zone `x` (apex and
  sub-domains); patterns with a wildcard inside cannot be expressed in DNS and
  are left to the engine; allow rules become `transparent` zones, which win over
  a blocked parent zone;
- pf tables `l7_ipb_<n>` (one per source scope, filled from a file; allow
  addresses are negated `!` entries, which pf resolves by the most specific
  match) with block rules in both directions.

The engine matches host patterns with `fnmatch` (case-insensitive, `*` crosses
dots; a leading `*.` also matches the bare domain) or, without wildcards, as a
domain suffix. Temporary rules carry an end time; `webexpire.sh` runs every
minute, costs nothing until the first expiry in `web_expiry`, then removes the
rule and applies. The quick action API (`webcontrol/quick`) adds or flips a rule
and runs Apply in the same call; new IP blocks also kill existing states with
`pfctl -k`.

## Live sessions

`live.py` reads `pfctl -ss -v`, pairs the translated halves of NAT states,
works out who started each connection and the direction (out, in, internal,
firewall) from the configured networks and the interface addresses, and joins
the engine's flow table (site name, application, country, decision) by client,
server and port, falling back to the newest name seen for the server address.
Rates are computed in the browser from the byte counters of two polls. The
engine now writes flow updates every 5 seconds (was 15) for the history view.

## Content filtering (CFS)

Categories are text files (`lists/<cat>.txt`, plus small built-in seeds) turned
into Unbound zones; group rules are policies marked `module=cfs` and use
Unbound views per source network; a rule that is restricted to signed-in users
without device addresses is skipped (DNS cannot tell the users apart). Safe
search is a set of `redirect` zones with a CNAME to the search engine's safe
host; YouTube restricted mode the same with `restrict.youtube.com`. The filter
include sets `log-local-actions`, so refused lookups appear in the Unbound log,
which `cfs.py log` reads for the activity lists. Known-bad address lists
(`threat/<id>.txt`) are pf tables `l7_thr_<id>` with block rules to and from them.

## DPI-SSL

One Squid in transparent SSL-bump mode (see AI content inspection) now serves
three purposes. The scope is *selected* (the engine steers the AI services chosen
for inspection, the antivirus sites and the administrator's list to the proxy
through `<l7_ai_bump>`) or *all* (pf redirects every TCP 443 to private-free
destinations to Squid, which splices the exclusion list and bumps the rest). A
**restricted** CA carries X.509 name constraints for the catalog, the antivirus
sites and the DPI sites; **all** needs a **full** CA, and Apply refuses a
certificate that does not fit. The default exclusions
(`share/layer7security/dpi_exclusions.txt`) cover certificate-pinned services.
Squid writes a small access log (`l7` format with the bump mode) that the
Sessions tab reads.

## Sign-in portal

`portal.py` (daemon, root) serves the login page over HTTPS on the firewall
address of each sign-in network (self-signed certificate created once) and a
loopback HTTP listener on 8081. pf redirects plain HTTP of devices that are not
in `<l7_auth_ok>` to 8081, which answers with a redirect to the login page, and
blocks their HTTPS and QUIC to non-private addresses (the login page, the web
interface and internal addresses stay reachable; IPv6 web traffic is blocked on
these networks). Passwords go to `authcheck.php` on stdin and are verified by
OPNsense's own authentication factory (local, LDAP, RADIUS), including optional
group membership. Failed logins are throttled per address. A session is
`auth.db` (address, user, MAC, times); `auth.py sync` writes `sessions.tsv`
(read by the engine, which matches policies that name users), the pf table
`<l7_auth_ok>` and one table `l7_usr_<policy>` per policy with users. The
proxy redirect rules only take signed-in addresses, so unsigned devices cannot
reach the proxy by a side door. The pf rules exist only while the portal runs
(`auth_ready` flag), so a failed portal never locks the network.

## Download protection (antivirus)

`avscan.py` serves `/av` (RESPMOD) from the ICAP server and decides on

- **file type**, from the first bytes and the file name (not the server's
  claim): programs, scripts, installer packages and archives; per type off,
  monitor or block;
- **hash reputation**: MD5, SHA-1 and SHA-256 of the downloaded file (transport
  compression removed) against the cloud lists (`av/cloud_<algo>.txt`, with
  malware family names where the source gives them), an optional own feed,
  the administrator's list and the EICAR test file;
- **signatures**: the YARA rules from the cloud server. `signatures.py` downloads
  the index, verifies each file's SHA-256, test-compiles every file on its own
  with `yarac` (one broken file never disables the rest) and compiles the good
  ones into `rules.yarc`; scanning runs the `yara` command line tool on a private
  temporary file, without a shell.

Plain HTTP is intercepted on `127.0.0.1:3128` (private destinations are never
redirected); HTTPS only for the sites listed or with DPI-SSL "all". Files larger
than the configured limit are not hashed (the type is still logged). Detections
are kept 90 days in `av.db`. It is not a full antivirus: it looks at one file at
a time, does not open archives and is as good as its public rules.

## Cloud feed server

`cloud/server/build_feeds.py` builds, hourly: `<category>.txt` (StevenBlack,
anudeepND, URLhaus, Phishing.Database, ThreatFox domains), `ip/<id>.txt` (Feodo,
ThreatFox, Emerging Threats, CINS, blocklist.de, Spamhaus DROP, Tor exits; only
public addresses are ever published), `hashes/<algo>.txt` (MalwareBazaar,
ThreatFox, the newest VirusShare MD5 lists), `yara/` (index with checksums, the
project's rules and the ReversingLabs rules that compile) and `manifest.json`
with sources and licences. A source that fails never empties an existing list.
`feedserver.py` serves only whitelisted names, with ETag and gzip. The plugin's
`feed_update.py` downloads with conditional requests, validates every line, and
refreshes on its own schedule (domains 6 h, bad addresses and hashes 3 h,
signatures 12 h; Apply downloads what is enabled but missing).

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
- The sign-in portal runs as root (it updates pf tables). It listens only on the
  firewall address of each sign-in network, limits request sizes and header time,
  escapes every dynamic text, checks the "go on" address (http or https only),
  protects the form with a per-address token and throttles wrong passwords
  (five failures lock an address for five minutes). Passwords travel to the PHP
  checker on stdin, never on a command line, and are never logged.
- Quick actions and uploads are validated before they reach configd: names are
  normalised (a single label such as "com" or a lone "*" is refused), hashes and
  paths match fixed patterns, uploaded files get a random name in a private
  directory and are deleted after the scan.
- A full DPI-SSL certificate can sign any site: treat the firewall like a CA and
  install the certificate only on managed devices.

## Known limits

- IPv4 interface networks are resolved for interface/VLAN scopes; IPv6
  clients are covered when listed explicitly as sources or users.
- Encrypted traffic is classified by SNI/ALPN/handshake metadata and nDPI's
  heuristics; ECH or VPN traffic may show as TLS/VPN only. TLS is decrypted
  only for the AI services and download sites an administrator selects (see
  AI content inspection); everything else is never decrypted.
- The first connection to a site right after a block rule is added can occasionally slip
  through (the address is learned from DNS or from that connection; later connections are
  dropped). In the lab this happened in about one fresh rule in four with the YouTube test,
  identically with the 0.2.0 engine, and could not be reproduced when the rule already existed.
- Blocking is per destination address; for shared CDN addresses the DNS name
  is the better handle (use host or DNS rules).
- Category lists (DNS) cannot tell signed-in users apart; rules for signed-in
  users work for applications, website names and AI services. Sign-in is per
  IPv4 address; devices behind another NAT share one session.
- The antivirus is a safety net (hashes, YARA rules, file types), not a full
  engine: archives are not opened, detection depends on the public rules.
- With DPI-SSL "all", a full CA is on the firewall: protect the firewall like
  a CA, install the certificate only on managed devices, and keep banks and
  health sites on the exclusion list.
- One engine process captures all selected interfaces; for very high line
  rates switch the capture backend to netmap (planned behind `on_packet`).
