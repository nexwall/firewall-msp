# netifyd analysis

## What it is

`netifyd` is the Netify Agent by eGloo Inc., a deep-packet-inspection (DPI) daemon built on the open-source nDPI
library. It classifies flows into applications, protocols and categories. NethSecurity uses it for:

- application-aware blocking and QoS (`ns-dpi`): netifyd labels connections in conntrack, nftables acts on the label
- traffic visibility (`ns-flows`, `ns-stats` from `nethsecurity-monitoring`; `ns.flows`, `ns.talkers`, `ns.dpireport`)
- inventory and HA hooks

Capture is via nfqueue (`table inet netifyd`, queues 50-57), only the first 32 packets of each flow are inspected.

## How this repo ships it

`packages/netifyd` has **no compile step**. It downloads prebuilt per-architecture binaries and plugin libraries from
`https://updates.nethsecurity.nethserver.org/netifyd-dist/...`, checks pinned SHA-256 hashes (`netify-dist.mk`), and
installs them. The Makefile declares `PKG_LICENSE:=Unlicensed`.

At runtime `ns-dpi` fetches `license.json`, data and subscription info from `distfeed.nethesis.it` and
`sp.nethesis.it`.

## Licensing facts (from Netify's public documentation)

| Piece | Status |
|---|---|
| Agent core | Open source on GitLab (`gitlab.com/netify.ai/public/netify-agent`), dual-licensed GPL/LGPL or commercial |
| `proc-core` plugin | Open source, GPLv3 or commercial |
| `proc-flow-actions` plugin | **Proprietary, license required.** This is the plugin `ns-dpi` uses to block/shape by application |
| `proc-aggregator` plugin | **Proprietary, license required** |
| `sink-http`, `sink-log` plugins | Not verified |
| Open application signature list | Apache-2.0, fewer than roughly 200 apps |
| Commercial application signature list | Proprietary, roughly 1,800+ apps, for paying subscribers |
| nDPI (underlying engine) | LGPL-3.0, maintained by ntop |

Consequence: the package license "Unlicensed" is not the GPL we rely on for the rest of the fork. We have **no
established right to redistribute** the Nethesis-hosted binaries inside Nexwall images. Downloading them for internal
test builds is one thing; shipping them to customers needs a written permission.

## Options for the fork

| Option | What it means | Effort | Result |
|---|---|---|---|
| **C. License from eGloo/Netify** | Commercial OEM agreement for the agent, flow-actions, aggregator and the full signature list; host binaries on our own feed | Business/legal | Full parity with the upstream DPI feature set, least engineering |
| **A. Build the open-source agent** | Compile netify-agent from GitLab (GPL), enable `proc-core`, use the open signature list; write our own replacement for flow-actions (label conntrack from classification) | Medium-high | Works legally, coverage limited to the small open signature list |
| **B. Own DPI service on nDPI** | Small daemon: libnetfilter_queue + libndpi, sets conntrack labels/marks, exposes flows to `ns-flows`; keep `ns-dpi` nft side | High | Fully ours and LGPL-clean, but we own signature quality and maintenance |
| **D. Ship without DPI** | Remove `netifyd`, `ns-dpi` and the DPI pages of the UI | Low code, wide surface | Loses app blocking, top talkers and flow views |

Suggested order: build the baseline image unchanged (netifyd included, for testing only), start the eGloo licensing
conversation in parallel, and keep **A** as the fallback if no agreement is reached. Do not ship customer images with
the Nethesis-hosted binaries until the licensing question is closed.

## What depends on netifyd (blast radius if removed or replaced)

`packages/ns-dpi`, `packages/ns-monitoring` (`ns-flows`, `ns-stats` plugin loaders), `packages/ns-api`
(`ns.dpi`, `ns.dpireport`, `ns.flows`, `ns.talkers`, `ns.netifyd`, `ns.ha`), `packages/python3-nethsec`
(`dpi`, `inventory`), `packages/telegraf` (`telegraf-services`), `packages/ns-ha`, `config/netifyd.conf`,
`config/connlabel.conf`, `files/etc/uci-defaults/99-nethsec-netifyd`, and the DPI/flows pages of `nethsecurity-ui`.
