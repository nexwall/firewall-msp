# NOTICE

Nexwall Firewall is a derivative work of free software projects. This file records attribution and licensing.

## Upstream projects

| Project | What was taken | Copyright | License |
|---|---|---|---|
| [NethSecurity](https://github.com/NethServer/nethsecurity) | build system, `ns-*` packages, root filesystem overlay, patches, configuration; forked at upstream commit `9a60b9c` | Nethesis S.r.l. and contributors | GPL-2.0-only for the build system and files that carry that tag; GPL-3.0-only for packages that declare it |
| [OpenWrt](https://github.com/openwrt/openwrt) | base system, toolchain and build system, fetched at tag `v25.12.5` during the build | OpenWrt contributors | GPL-2.0-only (with per-package licenses) |
| [OpenWrt packages feed](https://github.com/openwrt/packages) | several packages forked into `packages/` | OpenWrt contributors | per package, see `THIRD_PARTY_LICENSES.md` |

Components fetched from other repositories at build time are listed in `THIRD_PARTY_LICENSES.md`.

## Rules followed

1. Original copyright and license headers are never removed, even in files we modify.
2. Modified files are recorded in `FORK-CHANGES.md` (GPL-2.0 section 2(a)).
3. New Nexwall files carry `Copyright (C) <year> Nexwall` and `SPDX-License-Identifier: GPL-2.0-only`, unless a file
   states another license.
4. Anyone who receives a Nexwall Firewall image is entitled to the corresponding source under the terms of the GPL and
   LGPL. The source is this repository plus the revisions pinned in the package Makefiles.
5. The names "NethSecurity", "Nethesis" and "NethServer" are marks of their owners and are not licensed by the GPL.

## Full license texts

Under `LICENSES/`: GPL-2.0-only, GPL-3.0-only, Apache-2.0. The top-level `LICENSE` is kept unchanged from upstream.
