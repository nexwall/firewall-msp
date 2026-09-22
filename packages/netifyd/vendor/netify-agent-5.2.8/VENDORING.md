# Vendored source: Netify Agent v5.2.8-1

This is the working tree of `gitlab.com/netify.ai/public/netify-agent` at commit
`19458098898353ed1950cbdd35c85ee79c70a204` (tag `v5.2.8-1`), GPL-3.0-or-later, vendored here because
part of its normal build dependency chain is not independently fetchable:

- `libs/ndpi`, `libs/inih`, `libs/gperftools` are the vendor's real git submodules, public, checked out
  here at the exact commits recorded in the superproject's tree (`ndpi` `e440b7a4a`, `inih` `eda90a5`,
  `gperftools` `aea3a04`).
- `automake/` and `m4/` were also git submodules in the original tree
  (`netify-automake-includes`, `netify-autoconf-m4-includes`), but those two specific repositories
  require authentication we don't have and aren't meant for outside consumers. Their real content is
  the vendor's own git-describe-based release versioning, which this package doesn't use (the OpenWrt
  Makefile pins `PKG_VERSION` explicitly). They're replaced here with minimal stand-ins:
  - `automake/dist-git.am`: empty, satisfies the `include` directive in `Makefile.am`.
  - `m4/ax_check_progs.m4`, `m4/ax_git_vars.m4`: minimal `AC_DEFUN` stubs.
  - `m4/ax_pkg_installdir.m4`, `m4/ax_cxx_compile_stdcxx_11.m4`, `m4/ax_cxx_compile_stdcxx_17.m4`: the
    real macros (the first two are the vendor's own, not in the public autoconf-archive despite the
    naming; recovered from a successful earlier build of this same source lineage at v4.4.7, which used
    them unmodified. The `_17` variant is the real, unmodified file from the `autoconf-archive` package).

Verified: `autoreconf -fi` completes cleanly against this tree and produces a working `configure` script
(checked with `./configure --help`). The actual C++ compile has not been exercised outside the OpenWrt
package build.

`configure`, `Makefile.in` and other autotools-generated files are intentionally not vendored; the
package Makefile keeps `PKG_FIXUP:=autoreconf` and regenerates them at build time from this source.

## Correction (same day)

The first attempt at vendoring this tree ran a cleanup pass (removing leftover files from a
local `autoreconf` test run) that was not scoped narrowly enough: `find . -name "Makefile.in" -delete`
ran across the whole tree, including inside `libs/ndpi`, which genuinely ships pre-generated
`Makefile.in` files as tracked content (not something `autoreconf` needs to regenerate from
scratch here). That broke `automake` when the real OpenWrt build reached it
(`required file 'example/Makefile.in' not found`, and others). Fixed by re-cloning `libs/ndpi`,
`libs/inih` and `libs/gperftools` fresh and only stripping their `.git` directories this time -
nothing else inside them.
