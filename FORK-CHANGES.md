# Fork changes

Record of modifications to files inherited from NethSecurity (upstream commit `9a60b9c`), kept to satisfy the
"prominent notice of changes" requirement of GPL-2.0 section 2(a). Newest first.

## 2026-09-20

- **Sources**: `ns-ui`, `ns-monitoring`, `ns-dedalo` and `ns-checkmk-utils` are built from the Nexwall repositories,
  pinned to a commit. `PKG_SOURCE` is derived from the commit so a cached upstream tarball is never reused. `ns-ui`
  `PKG_RELEASE` 1 -> 2. The `URL:` field of `ns-objects`, `ns-api`, `ns-plug` and `ns-flashstart` points to
  `nexwall-controller`.
- **Traffic classification engine** (`packages/netifyd`): the package builds the open source Netify Agent v4.4.7
  from source (vendor repository, pinned commit `4d8d9210`, same version as the package in the OpenWrt packages feed)
  and no longer downloads any binary. It uses the init script and UCI config of the OpenWrt package, a new
  `netifyd.conf` (local event socket, upload service URL) and installs its data under `/etc/netifyd` with
  `/etc/netify.d` as a symlink. Removed: the v5 plugin configuration, the NFQUEUE setup script, the v4-to-v5
  migration script and `netify-dist.mk`.
- **DPI enforcement and analytics** (`packages/ns-dpi`): new daemon `ns-dpi-bridge` reads the flow events of the
  engine, forwards them to `ns-flows`, sends aggregated counters to `ns-stats` and adds the connections that match a
  rule of `/etc/config/dpi` to nftables sets. `dpi-nft` renders the sets and the rules that reject or re-prioritize them
  and validates them with `nft -c` before they replace the running rules. Unit tests in `packages/ns-dpi/tests`.
  `ns-monitoring` depends on `ns-dpi` and no longer installs plugin configuration.
- **API and library adjustments**: `ns.netifyd` uses the engine option names (`--enable-sink`, `--disable-sink`,
  `enable_sink`) and generates the agent UUID itself; `python3-nethsec` `dpi.load_protocols` skips lines that are not
  protocol entries.
- **Version**: image version `26.0.0-rc1` (`build.conf.defaults`).
- **Service endpoints**: hosts of the previous vendor services replaced by `services.nexwall.com.br` (registration,
  inventory, heartbeat, alerts, backup, telemetry, DPI data, log management), `updates.nexwall.com.br` (package feed,
  repository path `nethsecurity` -> `nexwall`) and `lists.nexwall.com.br` (blocklists). Paths are otherwise unchanged.
  Files: `ns-plug`, `ns-clm`, `ns-dpi`, `ns-phonehome`, `ns-threat_shield`, `ns-api`, `python3-nethsec`,
  `victoria-metrics`, `files/etc/uci-defaults/99-nethsec-backupurl`, `builder/configure-build.sh`.
- **DNS filter client** (`ns-flashstart`): API and dynamic DNS endpoints moved to `services.nexwall.com.br/dns`.
- **Blocklists**: feed identifiers, file names and labels renamed from the previous vendor names to `nexwall_*`
  (`ns-threat_shield`).
- **Defaults**: hostname `Nexwall`; default password `Nexwall,1234` (hash in
  `files/etc/uci-defaults/90-nethsec-root-password` regenerated; same value in the HA, API CLI and inventory defaults).
- **Runtime references**: the dashboard connectivity check no longer contacts the previous vendor site, the certificate account email and a DHCP example domain were changed (`ns.dashboard`, `ns.reverseproxy`, `ns.dhcp`).
- **Interface address handling** (`python3-nethsec` `nethsec.ipconf`, `ns.dhcp`, `ns.devices`, `ns.ovpnrw`): the code
  assumed every static interface has separate `ipaddr` and `netmask` options, which broke the DNS and DHCP page when
  OpenWrt wrote the address as `192.168.1.1/24` (option or list). A shared helper now reads every form and interfaces
  without a usable IPv4 address are skipped instead of raising an error. Unit tests in
  `packages/python3-nethsec/tests/test_ipconf.py`.
- **Wording**: product name in package descriptions, READMEs and messages; package category `Nexwall`.
- **Removed from the repository**: upstream documentation site, release and CI tooling, deployment examples, agent
  guides and repository automation.

## 2026-09-19

- **Branding** (`builder/configure-build.sh`): GRUB title, distribution name, product, manufacturer, home, support
  and bug URLs, package repository URL. Login banner link (`patches/package/base-files/100-base-files-banner.patch`).
  Image file name prefix `nethsecurity-` -> `nexwall-` (`packages/ns-plug/files/ns-download`).
- **Build parallelism** (`builder/entrypoint.sh`, `build-nethsec.sh`): `make -j` uses `MAKE_JOBS` when set,
  otherwise one job per CPU (previous behavior).
- **Licensing files**: `LICENSES/`, `NOTICE.md`, `FORK-CHANGES.md`, `THIRD_PARTY_LICENSES.md`, `README.md`.

Internal names (`ns-*` packages, the `nethsec` Python module, UCI option names, the build feed name) are deliberately
unchanged to keep future merges from upstream small. Original copyright headers are preserved everywhere.
