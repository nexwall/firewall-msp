# Fork changes

Record of modifications to files inherited from NethSecurity (upstream commit `9a60b9c`), kept to satisfy the
"prominent notice of changes" requirement of GPL-2.0 section 2(a). Newest first.

## 2026-09-20 - Build consumes the Nexwall forks (branch `msp/branding-licenses`)

- `packages/ns-ui`, `ns-monitoring`, `ns-dedalo`, `ns-checkmk-utils`: sources now come from `github.com/nexwall/*`
  pinned to a commit (see `msp/UPSTREAM_REPOS.md`). `PKG_SOURCE` is set from the commit so a cached upstream tarball
  is never reused. `ns-ui` `PKG_RELEASE` 1 -> 2.
- `ns-objects`, `ns-api`, `ns-plug`, `ns-flashstart`: package `URL:` field now points to `nexwall-controller`.
- `renovate.json`: automatic updates disabled for the four forked packages.

## 2026-09-20 - Service endpoints (branch `msp/branding-licenses`)

- All runtime endpoints that pointed to Nethesis / NethServer hosts (`my.nethesis.it`, `my.nethserver.com`,
  `backupd.nethesis.it`, `phonehome.nethserver.org`, `schema.nethserver.org`, `nar.nethesis.it`, `distfeed.nethesis.it`,
  `sp.nethesis.it`, `bl.nethesis.it`, `updates.nethsecurity.nethserver.org`) now use `services.nexwall.com.br`.
  Paths are unchanged. Files: `ns-plug`, `ns-clm`, `ns-dpi`, `ns-phonehome`, `ns-threat_shield`, `ns-api`
  (`ns.dashboard`, `ns.subscription`), `python3-nethsec`, `victoria-metrics` (`vmalert.initd`),
  `files/etc/uci-defaults/99-nethsec-backupurl`, `builder/configure-build.sh` (`CONFIG_VERSION_REPO`).
- `netifyd` sink URL (`netify-sink-http.json`, `netify-sink-http-auto.json`): `sink.netify.ai` -> `services.nexwall.com.br`.
- Not changed: the `netifyd` binary download in its Makefile. See `msp/OUTBOUND_ENDPOINTS.md`.

## 2026-09-20 - Default hostname (branch `msp/branding-licenses`)

- `files/etc/uci-defaults/99-nethsec-hostname`: first-boot hostname `NethSec` -> `Nexwall`.
  The web UI (fork `nexwall-ui`) warns about both the new and the legacy default.

## 2026-09-19 - Configurable build parallelism (branch `msp/branding-licenses`)

- `builder/entrypoint.sh`, `build-nethsec.sh`: `make -j` now uses `MAKE_JOBS` when set, otherwise one job per CPU
  (previous behaviour). Needed to build on hosts with little RAM, where one job per CPU runs out of memory.

## 2026-09-19 - Branding (branch `msp/branding-licenses`)

Modified inherited files:

- `builder/configure-build.sh`: image identity (GRUB title, distribution name, product, manufacturer, home, support
  and bug URLs, package repository URL) changed from NethSecurity/Nethesis to Nexwall.
  The repository URL `https://updates.nexwall.io/...` is a placeholder until that feed exists.
- `patches/package/base-files/100-base-files-banner.patch`: login banner documentation link.
- `packages/ns-plug/files/ns-download`: image file name prefix `nethsecurity-` -> `nexwall-`
  (must match `CONFIG_VERSION_DIST`, which sets the file name prefix of built images).
- `.github/workflows/build-image.yml`, `tools/issue-comment`: artifact file name globs updated to the new prefix.

Added files: `LICENSES/`, `NOTICE.md`, `FORK-CHANGES.md`, `THIRD_PARTY_LICENSES.md`, `README.md` (rewritten),
`msp/UPSTREAM_REPOS.md`, `msp/NETIFYD.md`, `msp/OUTBOUND_ENDPOINTS.md`.

Deliberately NOT changed: internal names (`ns-*` packages, `nethsec` python module, `NETHSECURITY_VERSION`, UCI
option names). Keeping them makes future merges from upstream cheap. Only user-visible strings are rebranded.
