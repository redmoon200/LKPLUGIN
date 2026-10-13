# User guide

## Install

On the firewall (OPNsense 26.1):

```sh
pkg add https://github.com/redmoon200/LKPLUGIN/releases/download/v0.1.0/os-layer7security-0.1.0.pkg
```

The package depends on `ndpi` and `sqlite3` from the OPNsense repository. Open
**Services > Layer 7 Security**.

## First steps

1. **Settings**: tick *Enabled*, choose the monitored (LAN or VLAN)
   interfaces, *Apply*. The engine starts and **Dashboard** and **Flows** fill
   within seconds.
2. **Policies**: add a policy. Match on *Applications* (nDPI names such as
   YouTube), *Application categories* (SocialNetwork, Game, VPN, ...) and/or
   *Host names*. Scope it by *Interfaces/VLANs*, *Source networks* and *Users*
   and set *Active days* and a time window. Choose *Monitor*, *Allow* or
   *Block*. Press *Apply*.
3. **Users**: give people a name and one or more addresses; use them in
   policies. (Use DHCP static mappings so addresses stay stable.)
4. **DNS Filtering**: enable it, pick categories, add always-block / allow
   domains. Optionally set a *Feed URL* (for example the cloud server
   `http://192.168.1.73:8080/feeds`) and press *Update lists now*.

Policies are evaluated in ascending *Sequence*; the first match wins, so put
`Allow` exemptions first.

## MAC binding

**Services > Layer 7 Security > MAC Binding**

1. Open *Discovered devices* (the engine must be running). Press *Bind* next to
   a device to bind the IP and MAC it uses now, or add bindings by hand. Leave
   the IP empty to allow-list a MAC only.
2. On the *Mode* tab choose **Protect** (a bound IP can only be used by its MAC)
   or **Strict** (additionally drops IPv4 from every device that is not bound),
   pick the enforced interfaces (LAN or VLAN) and press *Apply*.

Add every device you rely on **before** switching to Strict mode; a device that
is not bound (and not allow-listed by MAC) loses IPv4 connectivity on that
interface. Management access over another interface is not affected. Spoof
attempts show up as `mac-spoof` events and as *SPOOF* in the device list.

## GeoIP filtering

**Services > Layer 7 Security > GeoIP**

1. Tick *Enable GeoIP filtering*, press *Update database* once (refreshed weekly
   afterwards).
2. Add a policy: **Block** the selected countries or **Allow only** them,
   *Inbound* (traffic coming from the country, use the WAN interface),
   *Outbound* (your clients going to the country, use LAN/VLAN interfaces) or
   both, plus optional exceptions (addresses that are never affected).
3. Press *Apply*. The table below the policies shows entries and dropped
   packets per policy; the dashboard and flows page show the country of every
   flow.

*Allow only* never blocks private networks, so the firewall and local DNS stay
reachable. Country data is an approximation; use it as a coarse filter.

## AI services

**Services > Layer 7 Security > AI Services**

1. *Settings*: tick *Enable AI service control*, choose the default for services
   without a rule (*allow*, *monitor*, *block*) and what to do about QUIC
   (*off*, *AI services only*, *all UDP/443*).
2. *Rules*: add a rule per service (Claude, ChatGPT, Gemini, Copilot, Perplexity,
   DeepSeek and more): action, optional sources/users, days and hours.
   *Inspect content* sends that service through the inspection proxy.
3. *Usage* shows which services are used, by whom and how much.

Blocking works per destination address plus DNS, like the other policies. Block
QUIC if you want to inspect content: QUIC bypasses the proxy.

## AI content inspection and audit log

Read this before enabling: the firewall decrypts traffic to the services you
select. Tell the people concerned and keep to your local law.

1. **AI Audit > Privacy**: read the notice and acknowledge it. Nothing below can
   be applied before that. Then enable the audit log (*Settings* tab), optionally
   with a remote syslog target (recommended: it is the independent copy).
2. **AI Inspection > Certificate**: apply once with inspection enabled so the CA is
   created, download it and install it on every managed device (instructions on
   the page). Never install it on devices you do not manage.
3. **AI Inspection > Settings**: enable it and choose for each category (cards,
   identity numbers, API keys, source code) *off*, *monitor* or *block*. Tick
   *Inspect content* on the AI rules to be inspected (or *Inspect every AI
   service*). The *Test the detectors* tab shows what would be found in pasted text.
4. **AI Audit** lists AI use and detections with masked snippets only (for
   example `**** **** **** 1111`), verifies the hash chain, and exports CSV, JSON
   or JSONL.

Keep the audit retention and who may read the log in line with your policy: the
audit pages have their own privilege (*Services: Layer 7 Security: AI Audit log*).

## Download protection

**Services > Layer 7 Security > Antivirus**

This is download protection, not a virus scanner: it blocks files whose SHA-256 is
in a malware hash feed or your own list (and the EICAR test file), and it can log or
block risky file types (programs, scripts, installer packages, archives).

1. Set the actions per file type and for known hashes.
2. Optional: *Malware hash feed URL* (a text/CSV file with one SHA-256 per line,
   e.g. an abuse.ch MalwareBazaar export, which needs a free key) and *Your own
   blocked hashes*. *Status and feed* shows the number of hashes and the last update.
3. Plain HTTP downloads are checked automatically. For HTTPS, list the download
   sites under *Also scan HTTPS downloads from*; they are decrypted with the
   inspection CA (same privacy notice and CA installation as above; if the CA does
   not cover a new site, Apply tells you to replace it).
4. Test: download the EICAR test file from a client behind the firewall.

Trusted sites can be exempted under *Never scan these sites*.

## What each page shows

- **Dashboard**: flows, clients, applications, volume, blocked flows; traffic
  over time, top applications, categories, top clients, blocks per policy.
- **Flows**: searchable table of stored flows, filter by period or blocked
  only. Hostnames come from TLS SNI / HTTP / DNS.

## Operating notes

- Data lives in `/var/db/layer7security/l7.db` and is pruned after the
  configured retention. The engine log is `/var/log/layer7security.log`.
- Service control: `configctl layer7security start|stop|restart|status`.
- Block tables: `pfctl -t l7_blk_1 -T show`.
- *Enforce blocking* off turns block policies into log-only (dry run).
- After upgrading nDPI, run *Refresh application catalog* on the Settings page.

## Troubleshooting

| Symptom | Check |
|---|---|
| Dashboard empty | Engine running? (`configctl layer7security status`), correct interface selected, `/var/log/layer7security.log` |
| Block has no effect | Policy *Enabled* and inside its time window; *Enforce blocking* on; `pfctl -sr \| grep l7_blk`; source network covers the client |
| DNS filter has no effect | Client uses the firewall for DNS; Unbound running; `/usr/local/etc/unbound.opnsense.d/layer7security.conf` exists |
| A site stays reachable | Cached name/connection: the first lookup after a change is the one that arms the block; existing connections are killed on first sight. The very first connection right after adding a rule may occasionally get through; try again before assuming the rule is wrong |
