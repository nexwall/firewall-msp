# Fork changes

Record of modifications to files inherited from NethSecurity (upstream commit `9a60b9c`), kept to satisfy the
"prominent notice of changes" requirement of GPL-2.0 section 2(a). Newest first.

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
