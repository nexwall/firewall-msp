# Third-party components

Generated from the `PKG_LICENSE` fields in `packages/*/Makefile` at upstream commit `9a60b9c`. Regenerate when
package versions change. Components fetched from OpenWrt feeds keep the license declared by their own Makefile.

## Fetched from external repositories at build time

| Package | Version | Source | License |
|---|---|---|---|
| ns-ui | 2.24.1 | github.com/nexwall/nexwall-ui (fork of NethServer/nethsecurity-ui 2.24.1, pinned commit) | GPL-3.0-only |
| ns-monitoring | 1.2.1 | github.com/nexwall/nexwall-monitoring (fork of nethserver/nethsecurity-monitoring v1.2.1, pinned commit) | GPL-3.0-only |
| ns-dedalo | 0.0.4 | github.com/nexwall/captive-portal (fork of nethesis/icaro v85, pinned commit) | GPL-3.0-only |
| ns-checkmk-utils | 1.7.7 | raw files from github.com/nexwall/checkmk-tools (fork of nethesis/checkmk-tools, pinned commit, files identical to v1.7.7) | GPL-3.0-only (declared) |
| snort3 | 3.10.0.0 | github.com/snort3/snort3 | GPL-2.0-only |
| telegraf | 1.39.1 | github.com/influxdata/telegraf | MIT |
| victoria-metrics | 1.146.0 | github.com/VictoriaMetrics/VictoriaMetrics | Apache-2.0 |
| victoria-logs | 1.51.0 | github.com/VictoriaMetrics/VictoriaLogs | Apache-2.0 |
| acme-acmesh | 3.0.7 | github.com/acmesh-official/acme.sh | GPL-3.0-only |
| openvpn-easy-rsa | 3.2.5 | github.com/OpenVPN/easy-rsa | GPL-2.0 |
| keepalived | 2.3.3 | keepalived.org/software | GPL-2.0-or-later |
| checkmk-agent | upstream Checkmk | github.com/Checkmk/checkmk | GPL-2.0-only |

## Source lives in this repository (authored or forked upstream by Nethesis)

| Package | License |
|---|---|
| ns-api, ns-api-server, ns-binding, ns-clm, ns-dedalo (glue), ns-don, ns-dpi, ns-flashstart, ns-ha, ns-migration, ns-netmap, ns-objects, ns-openvpn, ns-phonehome, ns-plug, ns-reverse-proxy, ns-storage, ns-threat_shield, python3-nethsec | GPL-3.0-only (files may also carry a GPL-2.0-only SPDX header) |
| adblock 4.5.5, banip 1.8.10, rsyslog 8.2506.0 (forks of openwrt/packages) | GPL-3.0-or-later |
| mwan3 2.11.17 (fork of openwrt/packages) | GPL-2.0 |
| acme-common 1.1.2 (fork of openwrt/packages) | GPL-3.0-only |
| python-semver 3.0.4 (fork of openwrt/packages) | BSD-3-Clause |

## Not under a free license - action required

| Package | Version | Problem |
|---|---|---|
| netifyd | 5.2.9 | Makefile declares `PKG_LICENSE:=Unlicensed`. Prebuilt binaries and plugin libraries are downloaded from `updates.nethsecurity.nethserver.org`. Some plugins are documented by the vendor as proprietary and license-gated. See `msp/NETIFYD.md`. |

## Data files with their own terms

- `packages/netifyd/files/etc/netifyd/netify-apps.conf`: header states Apache-2.0 (eGloo open-source signature list).
- DNS blocklists in `packages/ns-threat_shield/files/*.sources` point at `bl.nethesis.it`; the lists are a Nethesis
  service, not part of the GPL source. See `msp/OUTBOUND_ENDPOINTS.md`.

## Base system

OpenWrt `v25.12.5` and its feeds are fetched during the build. Each package carries its own license, and the build
produces a manifest and SBOM (`config/sbom.conf`) listing what ended up in an image.
