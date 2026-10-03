# Changelog - v5.2.7

## [v5.2.7] - 2026-04-29

### Core Fixes & Improvements
- Fixed DHC loader.
- Fixed immortal idle flow leak during NFQUEUE conntrack sweeps.
- Fixed race condition causing a segfault in DPI queueing.
- Fixed conntrack event drops and switched to cumulative flow stats.
- Refactored various manual memory allocations to use smart pointers for better safety.
- Improved TCP sequence error detection and added a TCP retransmission counter.
- Removed unnecessary port byte-swapping.

### Performance Optimizations
- Optimized flow expiration using buckets and LRU lists.
- Improved PCAP performance and disabled immediate mode.
- Implemented a "fast path" for the ProcessPacket protocol.
- Switched from SHA1 to xxHash64 for flow digests and LRU caches.
- Optimized IP address comparisons (integer-based) and pre-calculated packet timestamp divisors.
- Deferred creation of `ndAddr` flow addresses and eliminated redundant data-link type branching.

### New Features
- Implemented stale conntrack flow purging (garbage collection).
- Added 56 new flow expression keywords for Network Details, Detection Flags, Protocol Metadata, and Metrics.
- Integrated GoogleTest for initial unit testing support.

### Configuration & Documentation
- Made conntrack garbage collection timeout configurable.
- Added `conntrack_idle_timeout` and `conntrack_buffer_size` to the default profile.
- Added and updated man pages, including a new flow expressions man page.
- Bumped version to v5.2.7.
