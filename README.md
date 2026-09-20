# Nexwall Firewall

Source code of Nexwall Firewall, an OpenWrt-based firewall distribution for managed service providers.

## Repositories

| Repository | Content |
|---|---|
| `nexwall/firewall-msp` | this repository: packages, configuration and image definition |
| `nexwall/nexwall-ui` | web interface (standalone and controller modes) |
| `nexwall/vue-components` | component library used by the web interface |
| `nexwall/nexwall-monitoring` | flow and statistics services |
| `nexwall/captive-portal` | captive portal (`dedalo` runs on the firewall) |
| `nexwall/checkmk-tools` | Checkmk local checks |
| `nexwall/nexwall-controller` | Central Management server |

## Layout

| Path | Content |
|---|---|
| `packages/` | packages of the distribution (`ns-*` and forks of OpenWrt packages) |
| `config/` | feature selection and per-target configuration |
| `files/` | root filesystem overlay |
| `patches/` | patches applied to upstream OpenWrt feeds |
| `builder/`, `build-nethsec.sh`, `build.conf.defaults` | image definition and build scripts |

Every package Makefile records the exact revision of the source it uses.

## License

GPL-2.0-only for the build scripts and files that carry that tag, GPL-3.0-only for the packages that declare it. Full
texts are in `LICENSES/`; attribution is in `NOTICE.md`; modifications are recorded in `FORK-CHANGES.md`; third-party
components are listed in `THIRD_PARTY_LICENSES.md`.
