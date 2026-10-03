#!/usr/bin/env bash
#!/bin/bash -x

# Debug CPPFLAGS for clang
# CPPFLAGS="-pipe -gdwarf-4 -O0"

: ${COMPILER:=gcc}
: ${CPPFLAGS:="-pipe -g -O1 -fexceptions -Wall"}
: ${LDFLAGS:=}
: ${VARIANT:=generic}
: ${ENABLE_SANITIZER:=false}
: ${ENABLE_STACK_PROTECTION:=false}
: ${OPTION_CONNTRACK:=enable}
: ${OPTION_CONNTRACK_MDATA:=enable}
: ${OPTION_CONNTRACK_COUNTERS:=enable}
: ${OPTION_NETLINK:=enable}
: ${OPTION_PLUGINS:=enable}
: ${OPTION_LIBTCMALLOC:=enable}
: ${OPTION_NFQUEUE:=enable}
: ${OPTION_LIBCAP:=enable}

: ${prefix:=/usr}
: ${exec_prefix:=${prefix}}
: ${bindir:=${prefix}/bin}
: ${sbindir:=${prefix}/sbin}
: ${sysconfdir:=/etc}
: ${datadir:=${prefix}/share}
: ${includedir:=${prefix}/include}
: ${libdir:=${prefix}/lib/x86_64-linux-gnu}
: ${libexecdir:=${prefix}/libexec}
: ${localstatedir:=/var}
: ${sharedstatedir:=/var/lib}
: ${mandir:=${prefix}/share/man}
: ${infodir:=${prefix}/share/info}

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig

if [ "x${ENABLE_SANITIZER}" != "xfalse" ]; then
  if [ "x${COMPILER}" == "xgcc" ]; then
    echo "Overriding COMPILER to clang, sanitizer enabled."
    COMPILER=clang
  fi
  if [ "x${OPTION_LIBTCMALLOC}" == "xenable" ]; then
    echo "Disabling OPTION_LIBTCMALLOC, sanitizer enabled."
    OPTION_LIBTCMALLOC=disable
  fi
fi

if [ "x${COMPILER}" == "xgcc" ]; then
  export CC=gcc
  export CXX=g++
  CPPFLAGS+=" -grecord-gcc-switches"
elif [ "x${COMPILER}" == "xclang" ]; then
  export CC=clang
  export CXX=clang++

  if [ "x${ENABLE_SANITIZER}" != "xfalse" ]; then
    CPPFLAGS+=" -fsanitize=${ENABLE_SANITIZER} -fno-omit-frame-pointer"
    LDFLAGS+=" -fsanitize=${ENABLE_SANITIZER}"
  fi
else
  echo "ERROR: Unsupported COMPILER: ${COMPILER}"
  exit 1
fi

if [ "x${ENABLE_STACK_PROTECTION}" == "xtrue" ]; then
  CPPFLAGS+=" -fstack-clash-protection -fstack-protector-strong \
    -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2"
fi

export CPPFLAGS="${CPPFLAGS}"
export LDFLAGS+="${LDFLAGS}"

case "x${VARIANT}" in
xgeneric)
  ;;
xcentos7x)
  ;;
xubuntu20x)
  ;;
*)
  echo "ERROR: Unsupported VARIANT: ${VARIANT}"
  exit 1
  ;;
esac

echo "Options:"
echo " COMPILER: ${COMPILER}"
echo " CPPFLAGS: ${CPPFLAGS}"
echo " LDFLAGS: ${LDFLAGS}"
echo " VARIANT: ${VARIANT}"
echo " ENABLE_SANITIZER: ${ENABLE_SANITIZER}"
echo " ENABLE_STACK_PROTECTION: ${ENABLE_STACK_PROTECTION}"
echo " OPTION_CONNTRACK: ${OPTION_CONNTRACK}"
echo " OPTION_CONNTRACK_MDATA: ${OPTION_CONNTRACK_MDATA}"
echo " OPTION_CONNTRACK_COUNTERS: ${OPTION_CONNTRACK_COUNTERS}"
echo " OPTION_NETLINK: ${OPTION_NETLINK}"
echo " OPTION_PLUGINS: ${OPTION_PLUGINS}"
echo " OPTION_LIBTCMALLOC: ${OPTION_LIBTCMALLOC}"
echo " OPTION_NFQUEUE: ${OPTION_NFQUEUE}"
echo " OPTION_LIBCAP: ${OPTION_LIBCAP}"

if [ $# -gt 0 -a "x$1" == "xhelp" ]; then exit 0; fi

CONFIGURE_ARGS="--program-prefix="
CONFIGURE_ARGS+=" --prefix=${prefix}"
CONFIGURE_ARGS+=" --exec-prefix=${exec_prefix}"
CONFIGURE_ARGS+=" --bindir=${bindir}"
CONFIGURE_ARGS+=" --sbindir=${sbindir}"
CONFIGURE_ARGS+=" --sysconfdir=${sysconfdir}"
CONFIGURE_ARGS+=" --datadir=${datadir}"
CONFIGURE_ARGS+=" --includedir=${includedir}"
CONFIGURE_ARGS+=" --libdir=${libdir}"
CONFIGURE_ARGS+=" --libexecdir=${libexecdir}"
CONFIGURE_ARGS+=" --localstatedir=${localstatedir}"
CONFIGURE_ARGS+=" --sharedstatedir=${sharedstatedir}"
CONFIGURE_ARGS+=" --mandir=${mandir}"
CONFIGURE_ARGS+=" --infodir=${infodir}"
CONFIGURE_ARGS+=" --${OPTION_CONNTRACK}-conntrack"
CONFIGURE_ARGS+=" --${OPTION_NETLINK}-netlink"
CONFIGURE_ARGS+=" --${OPTION_PLUGINS}-plugins"
CONFIGURE_ARGS+=" --${OPTION_LIBTCMALLOC}-libtcmalloc"
CONFIGURE_ARGS+=" --${OPTION_NFQUEUE}-nfqueue"
CONFIGURE_ARGS+=" --${OPTION_LIBCAP}-capabilities"

if [ "x${OPTION_CONNTRACK}" = "xenable" ]; then
    CONFIGURE_ARGS+=" --${OPTION_CONNTRACK_MDATA}-conntrack-mdata"
    CONFIGURE_ARGS+=" --${OPTION_CONNTRACK_COUNTERS}-conntrack-counters"
fi

./configure \
    $CONFIGURE_ARGS \
    $@ || exit $?

cat << EOF > compile_flags.txt
-std=gnu++11
-I./
-I../include/
-I./include/
-I./libs/inih/cpp/
-I./libs/ndpi/src/include/
-I./libs/gperftools/src/
-DHAVE_CONFIG_H
EOF

grep -E '^#define' config.h |\
  sed -e 's/^#define //' -e 's/^\(\w\+\) /-D\1=/' >> compile_flags.txt

exit 0
