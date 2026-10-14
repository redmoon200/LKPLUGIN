# User guide

This guide is for the people who run the firewall day to day. Every page has the
same layout: a **header** (what the page is, whether the module is on, an
**Apply changes** button), **tiles** with the numbers that matter, and **tabs**
(overview, rules or settings, activity).

Changes are saved when you click Save or finish a dialog, and put to work when
you click **Apply changes**. A yellow bar reminds you when something is waiting.
The quick actions of Live Sessions apply themselves.

## Install

On the firewall (OPNsense 26.1):

```sh
pkg add https://github.com/redmoon200/LKPLUGIN/releases/download/v0.5.0/os-layer7security-0.5.0.pkg
```

It installs `ndpi`, `sqlite3`, `squid` and `yara` from the OPNsense repository.
Three menus appear: **Layer 7**, **Protection** and **AI**.

## First steps (10 minutes)

0. **Layer 7 > License**: paste your license key, or enter the cloud server address and
   click *Start 30-day trial*. Without a license the protection stays off (traffic
   is not affected).
1. **Layer 7 > Settings**: tick *Enabled*, choose the LAN or VLAN interfaces to
   watch, *Apply changes*. **Layer 7 > Live Sessions** and the **Overview** fill
   within seconds.
2. **Protection > CFS > Settings**: tick *Enable content filtering*, *Save*, then the
   **Categories** tab to pick what to block (the cloud server address is on the License page). Devices must use the firewall as their DNS server.
3. **Protection > Web Control**: add the websites you never want (`*tiktok.com`).
4. **Protection > Application Control > Categories**: set VPN, P2P, games ...
   to *Block* or *Watch*.
5. Watch **Live Sessions** for a day and use its Block / Allow buttons to tune.

## Live Sessions (Layer 7)

Everything that is connected right now, refreshed every few seconds.

- **Connections**: device, website or address, port, application, country,
  download and upload speed, total, age and what was decided. Click a column to
  sort, use the chips to show outgoing, incoming, internal or the firewall's own
  connections, type to search. *Pause* freezes the list while you read it.
- **By device** and **By website** group the same data.
- **Blocked just now**: what was stopped in the last ten minutes, with an Allow
  button for mistakes.
- **History** is the searchable list of finished connections.

**Block** and **Allow** open one dialog: *what* (this website only, the whole
site `*.example.com`, or the IP address), *for whom* (everybody or only that
device), *how long* (always, 1 hour, 8 hours, 1 day, 7 days, 30 days) and an
optional note. Confirm and the rule is active in a few seconds; open
connections to a blocked address are cut. Rules from here appear in
**Protection > Web Control**, where you can edit, remove or make a temporary
rule permanent.

The click on **i** shows every detail of a connection.

## Web Control (Protection)

Allow and block lists for websites and IP addresses.

- Websites: `example.com` blocks the site and everything below it.
  `*.example.com` does the same. `*example.com` blocks every name that ends in
  it (also `cdnexample.com`). `ads*.example.net` and `?` work too. You can paste
  a whole address (`https://www.example.com/page`); only the name is kept.
- IP addresses: `203.0.113.7` or a network `203.0.113.0/24`.
- **Allow** rules are exceptions: `old.reddit.com` stays reachable although
  `*.reddit.com` is blocked, and they also beat category and application rules.
  Allow rules for IP addresses apply to everybody.
- **Applies to**: leave empty for everybody or enter device addresses or networks.
- **Test a website** shows which rules match a name.
- **Activity** lists what was stopped; **Settings** switches Web Control off
  without losing the rules.

How it blocks: the DNS filter answers "does not exist" for the site, and the
engine stops connections whose TLS or DNS name matches (so names that DNS cannot
express, like `ads*.example.net`, still work). Devices that use their own
encrypted DNS are still caught by the engine when the site name is visible.

## Application Control (Protection)

- **Categories**: one line per kind of application with Allow, Watch or Block.
- **Applications**: search the 467 applications the engine knows and set them
  one by one.
- **Advanced rules**: full rules with applications, categories or website names,
  for networks, devices, named users and hours. The first rule that matches wins.
- **Activity**: connections stopped by these rules.

## CFS: content filtering (Protection)

- **Categories**: tick what to block for everybody (advertising, trackers,
  malware, phishing, botnets, adult, gambling, social, streaming, games). The
  list shows how many websites each category holds.
- **Group rules**: block or allow categories for one network, some devices or
  certain hours. They need device addresses.
- **Settings**: the *blocked answer*, always-block and never-block websites,
  **safe search** (Google, Bing, DuckDuckGo) and **YouTube restricted mode**,
  **known bad addresses** (botnet servers, compromised hosts, attackers,
  hijacked networks, Tor).
- **Test a website** tells the category of a site; **Activity** lists refused
  lookups with an Allow button.

## DPI-SSL (Protection)

Lets the firewall look inside HTTPS. Read this first: it decrypts traffic, so
tell the people concerned and keep to your local law.

1. Acknowledge the privacy notice (**AI > AI Audit > Privacy**).
2. **Settings**: tick *Enable DPI-SSL*, choose *What to decrypt*:
   - *Only the sites listed* (default, safest): the sites you list, plus the AI
     services you chose for inspection and the download sites of Antivirus. The
     certificate is *restricted*: it can only be used for those sites.
   - *All HTTPS except the exclusions*: needs a *full* certificate (set
     *Certificate type* to Full, Save, create a new certificate). Banks, health
     sites and pinned apps belong on the exclusion list; a ready-made list of
     pinned services is skipped by default.
3. **Certificate**: *Download the certificate* and install it on every device you
   manage (instructions for Windows, macOS, Linux, Android and iOS are on the
   page). Never install it on devices you do not manage. *Create a new
   certificate* replaces it; every device then needs the new one.
4. *Apply changes*. **Sessions** shows decrypted and passed-through connections.

Apps that pin certificates, and sites using Encrypted Client Hello, cannot be
decrypted; put them on the exclusion list. QUIC (HTTP/3) bypasses the proxy:
block it under **AI > AI Service > Settings** if you rely on decryption.

## Antivirus (Protection)

Checks files that are downloaded through the firewall:

1. file type from the content (program, script, installer, archive);
2. MD5, SHA-1 and SHA-256 against malware lists (from the cloud server, your own
   list and the EICAR test file);
3. virus signatures (YARA rules from the cloud server).

*Settings*: choose Allow / Monitor / Block for each, start with Monitor for
signatures. Plain HTTP is checked automatically; for HTTPS list the download
sites or use DPI-SSL "all HTTPS". **Test a file** scans a file you upload and looks up a hash. The lists and
signatures are refreshed by the cloud connection (License page, *Check in and update now*).

It is a safety net, not a replacement for antivirus on the computers: archives
are not opened and the signature set is only as good as the public rules behind
it.

## Users and Access (Layer 7)

- **Named users and devices**: name people or devices by their addresses; use
  the names in Application Control, CFS group rules and AI rules.
- **Sign-in**: *Sign-in settings > Require sign-in for web access*, choose the
  network (LAN or VLAN with a static address), the authentication server
  ("Local Database" = the users under System > Access > Users, or LDAP or RADIUS
  servers), optional allowed groups, session length and idle time, and the
  devices that never need to sign in (your own computer first!). Devices that
  are not signed in are redirected to a login page when they open a website;
  HTTPS stays blocked until they sign in; DNS, mail and everything else keeps
  working. After sign-in, rules for the **named user** (same name as the
  account, addresses may be empty) apply to the device.
- **Signed-in users** shows who is signed in and lets you sign them out; the
  **Sign-in log** lists successful and failed attempts (five failures lock the
  address for five minutes).

Notes: sign-in works per IPv4 address (devices behind another NAT share one
sign-in) and IPv6 web traffic is blocked on sign-in networks. Rules for signed-in
users are enforced by application, website name and AI service; website
categories (DNS) need device addresses.

## MAC binding and GeoIP

**Layer 7 > MAC Binding**: bind an IP address to the MAC address that may use it;
*Strict* also blocks unknown devices. Add every device you rely on first.
**Layer 7 > GeoIP**: block or allow whole countries, inbound or outbound, with
exceptions; update the database once.

## AI

- **AI Service**: allow, watch or block each AI service (ChatGPT, Claude, Gemini,
  Copilot, Perplexity, DeepSeek ...) for everybody in one table; *Advanced rules*
  for groups and hours; *Usage* shows who uses what.
- **AI Inspection**: looks for card numbers, ID numbers, API keys and source code
  in what is sent to the services you tick *Check content* for. Needs DPI-SSL
  and the privacy notice. The test box shows what would be found.
- **AI Audit**: a tamper-evident log (hash chain) with masked excerpts only,
  verification, export (CSV, JSON), syslog and the privacy notice. It has its own
  privilege.

## The cloud server

`cloud/install.sh` installs the feed server on a Debian or Ubuntu machine. Every
hour it rebuilds from public sources: website categories, IP threat lists,
malware hashes (MalwareBazaar, ThreatFox, VirusShare) and YARA rules, and serves
them on port 8080 (`/feeds/manifest.json` lists what is inside and its terms).
Enter `http://<server>:8080/feeds` under **Layer 7 > License**. The
firewall refreshes the data every few hours by itself and reports in once an hour.
The dashboard on port 8090 shows builds, firewalls and has the license generator
(see [LICENSING.md](LICENSING.md)).

## Operating notes

- Data lives in `/var/db/layer7security/` and is pruned after the configured
  retention. The engine log is `/var/log/layer7security.log`, the sign-in portal
  logs to `/var/log/l7portal.log`, the proxy to `/var/log/l7squid/`.
- Service control: `configctl layer7security start|stop|restart|status`.
- Block tables: `pfctl -t l7_blk_1 -T show`.
- *Enforce blocking* off turns block policies into log-only (dry run).
- After upgrading nDPI, run *Refresh application catalog* on the Settings page.

## Troubleshooting

| Symptom | Check |
|---|---|
| Overview empty | Engine running? (`configctl layer7security status`), the right interface chosen in Layer 7 > Settings, `/var/log/layer7security.log` |
| A block has no effect | Rule enabled and inside its time window; *Enforce blocking* on; the device inside the rule's scope; `pfctl -sr \| grep l7_` |
| DNS filter has no effect | The device uses the firewall for DNS; Unbound running; `/usr/local/etc/unbound.opnsense.d/layer7security.conf` exists |
| Nobody can browse after turning on sign-in | The login page must be reachable: check Users and Access (status "Sign-in on"), add your own computer to *Never ask these devices* |
| Certificate warnings | The DPI-SSL certificate is not installed on the device, or the site is pinned: add it to the exclusions |
| Signatures not working | `pkg info yara`; the Antivirus tiles show the rule count; run *Check in and update now* on the License page |
| A site stays reachable | Cached name or connection: the first lookup after a change arms the block, open connections are killed on first sight. The very first connection right after a brand-new block rule may occasionally get through; try again before assuming the rule is wrong |

## License

**Layer 7 > License** shows whether the plugin is licensed, the type and end date
and the installation id of this firewall (needed for a key that is tied to it).

- *Activate key*: paste the key from your vendor. A running license is replaced
  only by a key that runs longer; a lifetime license is never replaced.
- *Start 30-day trial*: asks the cloud server for a trial key (once per firewall).
- *Check in and update now*: reports to the cloud server and downloads the lists.
- When the license ends or is withdrawn, the protection switches off by itself and
  this page opens; the network keeps working. A new key switches it on again.
