# Fork changes

Record of modifications to files inherited from NethSecurity (upstream commit `9a60b9c`), kept to satisfy the
"prominent notice of changes" requirement of GPL-2.0 section 2(a). Newest first.

## 2026-09-20

- **Sources**: `ns-ui`, `ns-monitoring`, `ns-dedalo` and `ns-checkmk-utils` are built from the Nexwall repositories,
  pinned to a commit. `PKG_SOURCE` is derived from the commit so a cached upstream tarball is never reused. `ns-ui`
  `PKG_RELEASE` 1 -> 2. The `URL:` field of `ns-objects`, `ns-api`, `ns-plug` and `ns-flashstart` points to
  `nexwall-controller`.
- **`netifyd`**: the package no longer downloads proprietary binaries. It installs a placeholder service
  (`files/usr/sbin/netifyd`) that keeps the interface used by `ns-api` and `python3-nethsec`, plus the open
  configuration and signature data. Removed `netify-dist.mk`.
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
