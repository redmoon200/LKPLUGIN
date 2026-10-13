# LKPLUGIN - os-layer7security

An open-source Layer-7 (application-aware) visibility and blocking plugin for
**OPNsense 26.x**. It identifies applications and categories with nDPI,
records flows to SQLite, shows them on a dashboard, and enforces policy through
pf tables and DNS filtering.

> **Status:** foundation only. See [docs/PROGRESS.md](docs/PROGRESS.md) and the
> roadmap in [CLAUDE.md](CLAUDE.md). Nothing here is production-ready yet.

## Layout

Follows the `opnsense/plugins` convention: the plugin lives in
`security/layer7security/`. Lab tooling is in `lab/`, design notes in `docs/`.

## Legal

This is an independent project. It is **not** affiliated with, endorsed by, or
derived from Zenarmor / Sunny Valley Networks, or the OPNsense project / Deciso
B.V. No code, assets or branding from those products are used. "OPNsense" is a
trademark of Deciso B.V.

## License

BSD 2-Clause. See [LICENSE](LICENSE).
