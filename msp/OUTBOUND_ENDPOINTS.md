# Outbound endpoints to Nethesis / NethServer

Every place where the shipped code talks to infrastructure owned by Nethesis. An image built from this repo will
send data to or fetch data from these hosts until each item is replaced or disabled. Found by scanning the tree at
upstream commit `9a60b9c`.

**Priority A = must be resolved before any customer deployment** (customer data leaves the network, or the firewall
can be pulled back to upstream releases).

| Pri | Endpoint | Where | What happens |
|---|---|---|---|
| A | `my.nethesis.it`, `my.nethserver.com` (`/api`, `/proxy/backup`, `/proxy/heartbeat`, `/proxy/inventory`, `/isa`) | `packages/ns-plug/files/register`, `send-inventory`, `send-heartbeat`, `remote-backup` | Registration, inventory, heartbeat, backup upload, alerts. Sends system data to Nethesis when a unit is registered |
| A | `backupd.nethesis.it` | `packages/ns-plug/files/config`, `files/etc/uci-defaults/99-nethsec-backupurl` | Default remote backup target |
| A | `phonehome.nethserver.org`, `schema.nethserver.org` | `packages/ns-phonehome` | Installation telemetry |
| A | `updates.nethsecurity.nethserver.org` | `packages/ns-plug/files/20_ns-plug`, `unregister`, `config`; `packages/netifyd/Makefile`; `tools/openwrt-changes` | Package repository URL and netifyd binaries. A registered unit can be pointed back at upstream feeds |
| A | `nar.nethesis.it` | `packages/ns-clm` | Central log management forwarder |
| A | `my.nethesis.it/proxy/alerts` | `packages/victoria-metrics/files/vmalert.initd` | Alert notifier |
| B | `distfeed.nethesis.it`, `sp.nethesis.it` | `packages/ns-dpi/files/dpi-*-update.py` | netifyd license, DPI data, subscription check |
| B | `bl.nethesis.it` | `packages/ns-threat_shield/files/community-dns.sources` | DNS blocklists (Nethesis service) |
| C | `nethserver.org/terms`, `nethserver.org/support`, `www.nethesis.it` | `packages/ns-api-server/files/src/main.go` (Swagger metadata), `ns-threat_shield/files/nethesis-dns.sources` | Descriptive links only |
| C | `updates.nethsecurity.nethserver.org` | `deploy/tofu.auto.tfvars.example`, `.github/` | Examples and CI |

## Already changed in this fork

`CONFIG_VERSION_REPO` (baked into the image package manager) now points to the placeholder
`https://updates.nexwall.io/<channel>/<version>`, so a fresh image no longer pulls packages from Nethesis.
Nothing else in the table has been changed yet.

## What we need to provide

1. **Update feed**: host apk packages, images and `sha256sums` under our own domain, signed with our own key pair
   (see `docs/build/index.md`, "Package signing").
2. **Registration, inventory, heartbeat, backup, alerts**: our own service replacing `my.nethesis.it`. The open
   `nethsecurity-controller` covers part of this (registration, VPN, proxy) and is the natural starting point.
3. **Telemetry**: disable `ns-phonehome` by default or point it at our own collector.
4. **DPI license and data**: depends on the netifyd decision, see `msp/NETIFYD.md`.
5. **Blocklists**: either mirror open lists or run our own.
