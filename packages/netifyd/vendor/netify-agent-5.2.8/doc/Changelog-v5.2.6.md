# Changelog - v5.2.6

## [v5.2.6-1]

### Core Fixes & Improvements
- Various address group fixes.
- Fixed bad endpoint and token logic.
- Fixed overlay tag/tag.group search order.
- Fixed flow expression evaluation for `app_cat != ...`.
- Free BPF filter memory.
- Proper handling of extra args.
- Ensure `digest_prev` is an array and `digest_prev[0]` is always set.
- Reversed and improved handling of digest and `digest_prev` in flow output.
- Renamed direction to `first_addr_cmp` for clarity.
- Moved layer offsets to packet class and reduced size using unions.
- Include `libmnl` when testing for presence of `nfq_nlmsg_put`.
- More compatible way to initialize a static atomic.
- Fixed typos and applied cosmetic changes.

### New Features
- Add Bridge PVID discovery and context-aware Netlink parsing.
- Add epoch support and permit epoch control over normal DoW rule.
- Added `total_lower/upper_bytes/packets` counters (#91).
- Added CIDR lookups for address groups.
- Added new conntrack flow expression keywords and intel criteria to flow expressions.
- Added `application_categories [ ]` to overlays and implemented custom categories.
- Added `enable` key support to capture interface configs.
- Added LRU cache TTL support.
- Added timer support for macOS.
- Support setting a tag for an API thread.
- Added experimental queue adapter and custom allocator.
- Add library and name to status output for UX integration.

### Configuration & Build
- Updated Docker configuration: Set DIND to v29, added `DOCKER_API_VERSION: "1.44"`, and pinned Docker-in-Docker service version.
- Skip OpenWrt `PKG_MIRROR_HASH` checking and updated version for OpenWrt 25.12.x.
- POST `license.json` on bootstrap when available.
- Updated automake sub-project.
- Added `debug-env.sh`.
- Removed unused header `linux/wireless.h` and moved includes to header.
