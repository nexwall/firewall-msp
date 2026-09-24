# Plugins

| File | License | Canonical source |
|---|---|---|
| `nx-proc-flows.cpp` | GPL-3.0-or-later | here (open source equivalent of the proprietary `proc-core`) |
| `nx-sink-http.cpp` | GPL-3.0-or-later | here (open source equivalent of the proprietary `sink-http`) |
| `nx-proc-aggregator.cpp` | Proprietary | [`nexwall/netify-plugins-pro`](https://github.com/nexwall/netify-plugins-pro) (private) - vendored here to build |
| `nx-proc-flow-actions.cpp` | Proprietary | [`nexwall/netify-plugins-pro`](https://github.com/nexwall/netify-plugins-pro) (private) - vendored here to build |
| `nx-sink-log.cpp` | Proprietary | [`nexwall/netify-plugins-pro`](https://github.com/nexwall/netify-plugins-pro) (private) - vendored here to build |

All five are written against the public, documented plugin ABI (`../../include/nd-plugin.hpp`)
and built in the same autotools pass as `netifyd` itself (`../Makefile.am`), so they share its
exact ABI by construction. See `msp/DPI_PLAN.md` in the internal repo for why: the real Netify
Agent plugins these replace turned out not to be buildable against, or ABI-compatible with, our
engine version.

`nx-proc-aggregator.cpp`, `nx-proc-flow-actions.cpp` and `nx-sink-log.cpp` are synced copies, not
developed here - edit them in `nexwall/netify-plugins-pro` and re-copy, not directly in this tree.

`nx-proc-aggregator` is loaded twice, under two tags with two different configs: `proc-ns-stats`
(ns-monitoring's own pipeline, feeding `sink-ns-stats` via HTTP) and `proc-aggregator` (the
vendor-equivalent pipeline, feeding `sink-log`, a local file `ns.talkers`/"Top consumers" in the
UI reads) - matching the real design's own two-instance architecture, not a Nexwall invention.
