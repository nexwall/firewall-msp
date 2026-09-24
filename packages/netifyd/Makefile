include $(TOPDIR)/rules.mk

PKG_NAME:=netifyd
PKG_VERSION:=5.2.8
PKG_RELEASE:=1
PKG_MAINTAINER:=Nexwall <dev@nexwall.com.br>
PKG_LICENSE:=GPL-3.0-or-later

PKG_BUILD_PARALLEL:=1
PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

# Open source Netify Agent (GPL), source at gitlab.com/netify.ai/public/netify-agent
# tag v5.2.8-1, commit 19458098898353ed1950cbdd35c85ee79c70a204. This is the same
# major version the original design used (inline NFQUEUE capture, native plugin
# loading), unlike the earlier Nexwall build of this package which used the
# community v4.4.7 (passive capture, no plugin loader).
#
# Vendored under ./vendor/netify-agent-5.2.8/ instead of fetched at build time:
# part of the vendor's normal submodule chain needs credentials we don't have
# (see vendor/netify-agent-5.2.8/VENDORING.md for exactly what and why). The
# three real vendor libraries it depends on (nDPI, inih, gperftools) are
# included at their exact pinned commits.
#
# The vendor ships an OpenWrt package template at deploy/openwrt/ inside this
# same source tree; this Makefile mirrors it (deploy/openwrt/Makefile.in),
# translated to concrete values.



include $(INCLUDE_DIR)/package.mk

define Package/netifyd
	SECTION:=admin
	CATEGORY:=Administration
	TITLE:=Traffic classification engine (Netify Agent)
	URL:=https://gitlab.com/netify.ai/public/netify-agent
	DEPENDS:= \
		@(aarch64||x86_64) \
		+ca-bundle \
		+libatomic \
		+libcurl \
		+libmnl \
		+libnetfilter-conntrack \
		+libnetfilter-queue \
		+libpcap \
		+libpthread \
		+libstdcpp \
		+libcap \
		+libubox \
		+libblobmsg-json \
		+libjson-c \
		+libubus \
		+libuci \
		+libnftnl \
		+nftables \
		+kmod-ipt-conntrack-label \
		+kmod-ipt-ipset \
		+libipset \
		+libgcrypt \
		+libgpg-error \
		+zlib \
		+zoneinfo-core \
		+python3-nethsec
endef

define Package/netifyd/description
The Netify Agent is a deep-packet inspection engine built on nDPI. It detects
network protocols and applications inline (NFQUEUE capture) and streams the
detections as JSON events, and can load plugins to act on them. Application
names come from the open signature list installed with the package; the
proprietary Nexwall plugins (see ns-dpi) add rule-based blocking, QoS marking
and traffic analytics.
endef

# The engine's own proc-core/sink-http plugins (both open source) are not
# part of the agent's own source tree - they are separate projects, and
# their source is not practically buildable (the vendor's own GitLab group
# for them requires access we don't have). Netify's prebuilt versions of
# them turned out to be ABI-incompatible with our own compiled engine (they
# expect libnetifyd.so.15, ours is .so.4 - a real gap between what the
# vendor publishes as source and what they distribute as binaries; see
# msp/DPI_PLAN.md in the internal repo for the full investigation). Instead,
# src/plugins/nx-proc-flows.cpp and src/plugins/nx-sink-http.cpp (in the
# vendored tree, wired into src/Makefile.am there) are our own equivalents,
# written against the same public, documented plugin ABI (nd-plugin.hpp)
# and the agent's own ndFlow::Encode(). Built and linked in the same
# autotools pass as netifyd itself, so ABI compatibility is guaranteed by
# construction rather than by version-pinning against an external release.
define Package/netifyd/conffiles
/etc/netifyd.conf
/etc/config/netifyd
/etc/netifyd/agent.uuid
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./vendor/netify-agent-5.2.8/. $(PKG_BUILD_DIR)/
endef

TARGET_CFLAGS+=-ffunction-sections -fdata-sections -Wno-psabi
TARGET_CXXFLAGS+=-ffunction-sections -fdata-sections -Wno-psabi -std=c++17
TARGET_LDFLAGS+=-Wl,--gc-sections -lgcrypt -lgpg-error

CONFIGURE_ARGS+= \
	--enable-shared \
	--enable-conntrack-counters \
	--enable-conntrack-mdata \
	--enable-extended-stats \
	--enable-interface-metadata \
	--enable-lean-and-mean \
	--enable-nfqueue \
	--enable-uci \
	--enable-ubus \
	--disable-tpacketv3 \
	--disable-capabilities \
	--with-local-libgcrypt \
	--with-stdcpp=17 \
	--sharedstatedir=/var/run \
	--disable-libtcmalloc \
	--without-systemdsystemunitdir \
	--without-tmpfilesdir

ifneq ($(CONFIG_LIBCURL_ZLIB),y)
CONFIGURE_ARGS+= --without-libcurl-zlib
endif

define Package/netifyd/install
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) ./files/netifyd.conf $(1)/etc/netifyd.conf
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/netifyd.config $(1)/etc/config/netifyd
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/netifyd.init $(1)/etc/init.d/netifyd
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/uci-defaults/99-netify-enable-nfqueue $(1)/etc/uci-defaults/99-netify-enable-nfqueue
	$(INSTALL_BIN) ./files/uci-defaults/99-netify-disable-autoconfig $(1)/etc/uci-defaults/99-netify-disable-autoconfig
	$(INSTALL_BIN) ./files/uci-defaults/99-netify-disable-coredumps $(1)/etc/uci-defaults/99-netify-disable-coredumps
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/netifyd $(1)/usr/sbin
	$(INSTALL_BIN) ./files/ns-netifyd-configure $(1)/usr/sbin/ns-netifyd-configure
	# libnetifyd.so itself (built shared - see --enable-shared above), needed
	# at runtime for the two plugins below to resolve their symbols against;
	# and our own nx-proc-flows/nx-sink-http plugins (src/plugins/ in the
	# vendored tree, wired into src/Makefile.am there), open-source
	# equivalents of the real proc-core/sink-http, not buildable against this
	# engine version - see msp/DPI_PLAN.md in the internal repo. $(CP)
	# preserves the SONAME symlinks libtool already creates.
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libnetifyd.so* $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libnx-proc-flows.so $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libnx-sink-http.so $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libnx-proc-aggregator.so $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libnx-proc-flow-actions.so $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/etc/netifyd
	$(INSTALL_DIR) $(1)/etc/netifyd/address-groups.d
	$(INSTALL_DIR) $(1)/etc/netifyd/categories.d
	$(INSTALL_DIR) $(1)/etc/netifyd/profiles.d
	$(CP) $(PKG_INSTALL_DIR)/etc/netifyd/profiles.d/* $(1)/etc/netifyd/profiles.d
	$(INSTALL_DIR) $(1)/etc/netifyd/interfaces.d
	$(CP) $(PKG_INSTALL_DIR)/etc/netifyd/interfaces.d/* $(1)/etc/netifyd/interfaces.d
	# the real, active NFQUEUE capture config (role-based, matches the real
	# NethSecurity design) - the files copied just above are only the
	# vendor's own inert usage examples
	$(INSTALL_DATA) ./files/10-nfqueue.conf $(1)/etc/netifyd/interfaces.d/10-nfqueue.conf
	$(INSTALL_DIR) $(1)/etc/netifyd/plugins.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/deploy/netify-apps.conf $(1)/etc/netifyd
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/deploy/netify-categories.json $(1)/etc/netifyd
	$(INSTALL_DIR) $(1)/usr/share/netifyd/plugins.d
	$(INSTALL_DATA) ./files/netifyd.conf $(1)/usr/share/netifyd/netifyd.conf.default
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/deploy/functions.sh $(1)/usr/share/netifyd
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/deploy/netify-apps.conf $(1)/usr/share/netifyd
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/deploy/*.json $(1)/usr/share/netifyd
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/deploy/plugins.d/*.conf $(1)/usr/share/netifyd/plugins.d
endef

$(eval $(call BuildPackage,netifyd))
