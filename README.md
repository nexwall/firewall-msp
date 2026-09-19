# Nexwall Firewall (MSP edition)

An OpenWrt-based firewall for managed service providers, forked from
[NethSecurity](https://github.com/NethServer/nethsecurity) (upstream commit `9a60b9c`), a downstream rebuild of
[OpenWrt](https://openwrt.org/).

The upstream remote is kept as `upstream` so we can merge upstream fixes. Internal names (`ns-*` packages, `nethsec`
python module, UCI options) are intentionally unchanged to keep those merges cheap.

## Build

Requires Linux with rootless Podman 4.x, 8+ GB RAM, 100+ GB free disk and 8+ CPU cores.

```
./build-nethsec.sh
```

Output goes to `bin/` (images and packages) and `build-logs/`. The image is
`bin/targets/x86/64/*-combined-efi.img.gz` (UEFI disk image, written to disk with `dd`). See `docs/build/index.md`.

## Where things are

| Path | Content |
|---|---|
| `builder/`, `build-nethsec.sh` | Podman build container and driver |
| `packages/` | Local OpenWrt feed (`ns-*` packages and forks) |
| `config/` | Feature fragments and per-target config |
| `files/` | Root filesystem overlay |
| `patches/` | Patches applied to upstream OpenWrt feeds |
| `msp/` | Fork documentation: upstream repos, netifyd analysis, outbound endpoints |
| `LICENSES/`, `NOTICE.md`, `THIRD_PARTY_LICENSES.md`, `FORK-CHANGES.md` | Licensing and attribution |

## License

GPL-2.0-only for the build system and files carrying that tag; GPL-3.0-only for packages that declare it.
See `NOTICE.md`. Some components are not free software, see `msp/NETIFYD.md`.
