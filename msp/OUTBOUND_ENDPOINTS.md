# Outbound endpoints

Every place where the shipped code talks to infrastructure outside the firewall.

As of 2026-09-20 all runtime endpoints that used to point to Nethesis / NethServer hosts point to a single host,
**`services.nexwall.com.br`**, with the paths unchanged from upstream. The FQDN is the only difference, so future
merges from upstream stay small. Until that host serves these paths, the features below fail (they do not fall back
to Nethesis).

## What `services.nexwall.com.br` has to serve

| Function | Component | Paths used (unchanged from upstream) | Notes |
|---|---|---|---|
| Registration, subscription | `ns-plug` (`register`, `unregister`), `ns.subscription` | `/api/` | system id and secret issued here |
| Inventory | `ns-plug` (`send-inventory`), `python3-nethsec` | `/api/systems/info`, `/proxy/inventory`, `/isa/inventory/store/`, `/api/machine/inventories/store/` | legacy formats kept as upstream |
| Heartbeat | `ns-plug` (`send-heartbeat`) | `/proxy/heartbeat` | basic auth: system id / secret |
| Alerts | `ns-plug-alert-proxy`, `vmalert` | `/proxy/alerts`, `/isa/`, `/api/machine/` | |
| Remote backup | `ns-plug` (`remote-backup`, `backup_url`) | `/`, `/backup`, `/proxy/backup` | |
| Package feed | `ns-plug` (`distfeed-setup`), `unregister`, `CONFIG_VERSION_REPO` | `/<channel>/<version>/...`, `/repository/<type>/nethsecurity` | apk repositories, images, `sha256sums` |
| DPI license, data, subscription check | `ns-dpi` (`dpi-*-update.py`) | root of the host, see the scripts | |
| Central log management | `ns-clm` | root of the host | |
| Installation telemetry | `ns-phonehome` | `/api/installation`, `$schema` `/facts/2022-12.json` | |
| DNS and IP blocklists | `ns-threat_shield` | `/plain/...` | enterprise lists use basic auth (`__USER__:__PASSWORD__`) |
| Traffic Analytics sink | `netifyd` (`netify-sink-http*.json`) | `/v1/` | opt-in, off by default |
| Traffic Analytics portal | web UI | `/login` | opened from the Traffic Analytics page |

One host serves many functions: the backend behind it must route by path. `/api/` is shared by registration and
telemetry.

## Not changed on purpose

| Item | Where | Why |
|---|---|---|
| `netifyd` binary download | `packages/netifyd/Makefile` (`updates.nethsecurity.nethserver.org/netifyd-dist/`) | Build-time dependency. Changing it breaks the image build until the files are hosted (and their license is settled, see `NETIFYD.md`). |
| Release tooling and examples | `tools/openwrt-changes`, `deploy/tofu.auto.tfvars.example`, `.github/` | Not shipped in the image. Point them to the new feed once it publishes releases. |
| FlashStart signup links | web UI (`flashstart.nethesis.it`) | Third-party reseller portal, needs a business decision. |
| Comments naming legacy hosts | `ns-plug`, `python3-nethsec`, `vmalert` | Explanatory only. |

## Also to decide

- Blocklist provider names shown in the UI (Nethesis, Yoroi) describe real data sources; rename them only if you
  host equivalent lists under your own name.
- `ns-phonehome` sends installation telemetry. Keep it only if the collector at `/api/installation` exists.
