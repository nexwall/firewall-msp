# Upstream repositories

Which repositories make up a NethSecurity-derived firewall, what each one does, and whether we need our own fork.
Versions are the ones pinned at upstream commit `9a60b9c`.

## A. Fork these (needed to build or to own the product)

| Repository | Role | Pinned at | How the build uses it |
|---|---|---|---|
| `NethServer/nethsecurity` | Base: builder, packages, config, overlay, patches | `9a60b9c` | **This repo** (already forked as `nexwall/firewall-msp`) |
| `NethServer/nethsecurity-ui` | Vue 3 management web UI (branding, logos, texts live here) | tag `2.24.1` | `ns-ui` clones it by git tag during the build |
| `NethServer/nethsecurity-monitoring` | Go tools `ns-flows` / `ns-stats` reading netifyd flows | tag `v1.2.1` | `ns-monitoring` clones it by git tag |
| `nethesis/icaro` | Captive portal (hotspot), packaged as `ns-dedalo` | tag `v85` | `ns-dedalo` clones it by git tag |
| `nethesis/checkmk-tools` | Checkmk check scripts | tag `v1.7.7` | `ns-checkmk-utils` downloads raw files from it |

## B. Fork for the MSP management side (not fetched by the image build)

| Repository | Role |
|---|---|
| `NethServer/nethsecurity-controller` | Central controller: firewall registration, VPN and proxy routing, remote access. This is the natural core of an MSP console. |
| `NethServer/ns8-nethsecurity-controller` | Packaging of the controller as an NS8 module (only if you deploy on NS8) |
| `NethServer/nethsecurity-docs` | Administrator manual (docs.nethsecurity.org), to rebrand as your documentation |

## C. Already inside this repository (no separate fork needed)

| Code | Location | Upstream repo, for history only |
|---|---|---|
| REST API server (Go) | `packages/ns-api-server/files/src` | `NethServer/nethsecurity-api` |
| Python library `nethsec` | `packages/python3-nethsec/src` | `NethServer/python3-nethsec` |
| RPCD APIs, dpi, plug, storage, ha, ... | `packages/ns-*` | this repo |

## D. Third-party sources fetched at build time (mirror them for supply-chain safety)

| Repository | Version | Note |
|---|---|---|
| `openwrt/openwrt` | `v25.12.5` | Base system |
| `openwrt/packages`, `openwrt/luci`, `openwrt/telephony` | per OpenWrt tag | Feeds. `routing` and `video` are removed by the Containerfile. |
| `snort3/snort3` | 3.10.0.0 | IPS |
| `influxdata/telegraf` | 1.39.1 | Metrics agent |
| `VictoriaMetrics/VictoriaMetrics`, `VictoriaMetrics/VictoriaLogs` | 1.146.0 / 1.51.0 | Metrics and logs storage |
| `acmesh-official/acme.sh`, `OpenVPN/easy-rsa`, keepalived.org | see `THIRD_PARTY_LICENSES.md` | |

## E. Not in any repository

| Item | Where it comes from | Impact |
|---|---|---|
| `netifyd` binaries and plugins | `updates.nethsecurity.nethserver.org` (Nethesis server) | See `msp/NETIFYD.md` |
| Update feed (apk repos, images, sha256sums) | `updates.nethsecurity.nethserver.org` | We must host our own (`updates.nexwall.io` placeholder) |
| `my.nethesis.it` portal (subscription, inventory, heartbeat, backup proxy) | Closed service | We must provide our own equivalents, see `msp/OUTBOUND_ENDPOINTS.md` |

## Clone commands

```
git clone https://github.com/NethServer/nethsecurity-ui.git
git clone https://github.com/nethserver/nethsecurity-monitoring.git
git clone https://github.com/nethesis/icaro.git
git clone https://github.com/nethesis/checkmk-tools.git
git clone https://github.com/NethServer/nethsecurity-controller.git
git clone https://github.com/NethServer/nethsecurity-docs.git
```

Forking the repositories in group A means changing each package Makefile `PKG_SOURCE_URL` to the fork and pinning a
tag. Until then the build fetches the Nethesis originals, which is fine for the baseline image.

## How the image build consumes the forks (2026-09-20)

| Package | Fork | Pinned commit | Upstream content it equals |
|---|---|---|---|
| `ns-ui` | `nexwall/nexwall-ui` | `bb05a424d8124cb478c60973ec3b21095538c408` (branch `feature/menu-restructure`) | 2.24.1 plus Nexwall changes |
| `ns-monitoring` | `nexwall/nexwall-monitoring` | `403140ed9be858d69f062dd14f0fef3ff3a1c06d` (`main`) | v1.2.1 (only CI workflows differ) |
| `ns-dedalo` | `nexwall/captive-portal` | `9b78ac0eae415094ec9449646aedeb5d4d10d963` (branch `pin/v85`) | v85 exactly (the mirrored `main` is newer and lacks `walled_gardens/instagram.conf`) |
| `ns-checkmk-utils` | `nexwall/checkmk-tools` | `06b5a811bec0922bf6f029f91700758678e7bf40` (`main`) | the 10 checks used are identical to v1.7.7 |

Not consumed by the image build: `nexwall-controller` (server side), `nexwall-docs`.

To ship a change: commit in the fork, push, put the new full commit hash in the package Makefile
(`PKG_SOURCE_VERSION`, or `NS_CHECKMK_UTILS_BASE_URL` for checkmk), and bump `PKG_RELEASE`.
Each package sets `PKG_SOURCE` from the commit hash on purpose: OpenWrt names the cached tarball after the package
version, and the builder keeps a persistent `dl` volume, so without it a stale upstream tarball would be reused.
`GO_PKG` in `ns-monitoring` stays `github.com/nethserver/nethsecurity-monitoring`: it is the Go module path.
