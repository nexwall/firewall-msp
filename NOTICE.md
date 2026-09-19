# NOTICE

**Nexwall Firewall (MSP edition)** is a derivative work of free software projects.
This file records attribution and licensing so that anyone receiving a build can see where the code came from.

## Upstream projects

| Project | What we took | Copyright | License |
|---|---|---|---|
| [NethSecurity](https://github.com/NethServer/nethsecurity) | The whole repository: build system, `ns-*` packages, root filesystem overlay, patches, configuration fragments. Forked at upstream commit `9a60b9c`. | Nethesis S.r.l. and contributors | GPL-2.0-only for the build system and files carrying that SPDX tag; GPL-3.0-only for the packages that declare it in their Makefile |
| [OpenWrt](https://github.com/openwrt/openwrt) | Base system, toolchain and build system, fetched at tag `v25.12.5` during the build | OpenWrt contributors | GPL-2.0-only (with per-package licenses) |
| [OpenWrt packages feed](https://github.com/openwrt/packages) | Several packages forked into `packages/` (adblock, banip, mwan3, acme, rsyslog, ...) | OpenWrt contributors | Per package, see `THIRD_PARTY_LICENSES.md` |

Components fetched from other repositories at build time are listed in `THIRD_PARTY_LICENSES.md`.

## Rules we follow

1. **Original copyright and license headers are never removed.** Files that say
   `Copyright (C) <year> Nethesis S.r.l.` keep that line even after we modify them.
2. **Modified files are recorded.** GPL-2.0 section 2(a) requires prominent notice that files were changed and when.
   `FORK-CHANGES.md` is that record; every change to an inherited file gets an entry.
3. **New Nexwall-authored files** carry:
   ```
   # Copyright (C) <year> Nexwall
   # SPDX-License-Identifier: GPL-2.0-only
   ```
   unless a file states another license.
4. **Source offer.** Anyone who receives a Nexwall Firewall image is entitled to the corresponding source for the
   GPL/LGPL components under the terms of those licenses. The complete source is this repository plus the pinned
   upstream revisions listed in `msp/UPSTREAM_REPOS.md`.
5. **Trademarks.** "NethSecurity", "Nethesis" and "NethServer" are marks of their owners and are not licensed by
   the GPL. This fork uses its own name and identity.

## Components that are NOT under a free license

See `msp/NETIFYD.md`. The `netifyd` package installs prebuilt binaries whose package license is recorded upstream as
`Unlicensed`. Redistribution rights for those binaries have not been established for this fork.

## Full license texts

Under `LICENSES/`: GPL-2.0-only, GPL-3.0-only, Apache-2.0. The existing top-level `LICENSE` file is kept unchanged
from upstream.
