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
| A site stays reachable | Cached name/connection: the first lookup after a change is the one that arms the block; existing connections are killed on first sight |
