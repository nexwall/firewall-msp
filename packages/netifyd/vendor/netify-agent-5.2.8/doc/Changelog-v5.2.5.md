# Changelog - v5.2.5

## [v5.2.5-1]

### Core Fixes & Improvements
- Fixed IPv6 append `MakeString()` issue.
- Fixed missing enum.
- Fixed debug output.
- Don't clear group filenames on load.
- Deprecated `ADD_CR` for `ADD_LF`.
- Added check for assert header.
- Cosmetic cleanup and removed unnecessary period.

### New Features
- Added support for applying a mark w/mask on NFQ packets.
- Added instance restart support.
- Added flow feeds endpoint.
- Added reload API socket command.
- Display Agent and nDPI minimum flow sizes.
- Added format mask to `DispatchFlags`.

### Configuration & Build
- Updated generated files.
