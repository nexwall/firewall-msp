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

# Two of the engine's own plugins (both open source, GPL-3.0-or-later /
# LGPL-3.0-or-later depending on build) are not part of the agent's own source
# tree - they are separate projects, and their source is not practically
# buildable (the vendor's own GitLab group for them requires access we don't
# have; see msp/DPI_PLAN.md in the internal repo). Netify publishes them
# prebuilt, the same official channel the original NethSecurity design itself
# used (their own Makefile downloaded prebuilt .so files from a private
# mirror of these same packages). Pinned here from the OpenWrt 24.10 feed
# (25.12 only publishes the newer binary "adb" index format, not practically
# parseable from this build environment); these are shared-library plugins
# with stable dependency SONAMEs, expected to load correctly against our
# 25.12-built agent, but this has not yet been confirmed by actually running
# them - do that before relying on this in production.
NETIFY_PLUGIN_BASE_URL:=https://download.netify.ai/5/openwrt/24.10/x86

define Download/netify-proc-core
  URL:=$(NETIFY_PLUGIN_BASE_URL)
  URL_FILE:=netify-proc-core_1.2.3.20260701-r8_x86_64.ipk
  FILE:=netify-proc-core_1.2.3.20260701-r8_x86_64.ipk
  HASH:=a3fc6146fe56fc841c8b7ab3061ae0cec2a85675263fa586ca6e7513d6022904
endef
$(eval $(call Download,netify-proc-core))

define Download/netify-sink-http
  URL:=$(NETIFY_PLUGIN_BASE_URL)
  URL_FILE:=netify-sink-http_1.2.3.20260701-r7_x86_64.ipk
  FILE:=netify-sink-http_1.2.3.20260701-r7_x86_64.ipk
  HASH:=8f12dc0162509b7f73a62ddd155a73b828d1c4dbb00c83b14857619a236773a4
endef
$(eval $(call Download,netify-sink-http))

define Package/netifyd/conffiles
/etc/netifyd.conf
/etc/config/netifyd
/etc/netifyd/agent.uuid
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./vendor/netify-agent-5.2.8/. $(PKG_BUILD_DIR)/
	# extract the two prebuilt plugin .ipk files: each is a gzip'd tar containing
	# debian-binary, control.tar.gz and data.tar.gz; only data.tar.gz's usr/lib/*.so*
	# is needed, tar -xz preserves the symlinks it already contains
	mkdir -p $(PKG_BUILD_DIR)/_plugins/proc-core $(PKG_BUILD_DIR)/_plugins/sink-http
	$(TAR) -xzf $(DL_DIR)/netify-proc-core_1.2.3.20260701-r8_x86_64.ipk -C $(PKG_BUILD_DIR)/_plugins/proc-core ./data.tar.gz
	$(TAR) -xzf $(PKG_BUILD_DIR)/_plugins/proc-core/data.tar.gz -C $(PKG_BUILD_DIR)/_plugins/proc-core ./usr/lib
	$(TAR) -xzf $(DL_DIR)/netify-sink-http_1.2.3.20260701-r7_x86_64.ipk -C $(PKG_BUILD_DIR)/_plugins/sink-http ./data.tar.gz
	$(TAR) -xzf $(PKG_BUILD_DIR)/_plugins/sink-http/data.tar.gz -C $(PKG_BUILD_DIR)/_plugins/sink-http ./usr/lib
endef

TARGET_CFLAGS+=-ffunction-sections -fdata-sections -Wno-psabi
TARGET_CXXFLAGS+=-ffunction-sections -fdata-sections -Wno-psabi -std=c++17
TARGET_LDFLAGS+=-Wl,--gc-sections -lgcrypt -lgpg-error

CONFIGURE_ARGS+= \
	--disable-shared \
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
	$(INSTALL_BIN) ./files/netifyd-selfheal.init $(1)/etc/init.d/netifyd-selfheal
	$(INSTALL_BIN) ./files/netifyd-zones.init $(1)/etc/init.d/netifyd-zones
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/hotplug.d.iface/20-netifyd $(1)/etc/hotplug.d/iface/20-netifyd
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/netifyd $(1)/usr/sbin
	$(INSTALL_BIN) ./files/ns-netifyd-configure $(1)/usr/sbin/ns-netifyd-configure
	# proc-core and sink-http plugins (prebuilt, see Build/Prepare above and
	# vendor/netify-agent-5.2.8/VENDORING.md); $(CP) preserves the symlinks
	# already present in the extracted tree (SONAME -> real file)
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/_plugins/proc-core/usr/lib/libnetify-proc-core.so* $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/_plugins/sink-http/usr/lib/libnetify-sink-http.so* $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/etc/netifyd
	$(INSTALL_DIR) $(1)/etc/netifyd/address-groups.d
	$(INSTALL_DIR) $(1)/etc/netifyd/categories.d
	$(INSTALL_DIR) $(1)/etc/netifyd/profiles.d
	$(CP) $(PKG_INSTALL_DIR)/etc/netifyd/profiles.d/* $(1)/etc/netifyd/profiles.d
	$(INSTALL_DIR) $(1)/etc/netifyd/interfaces.d
	$(CP) $(PKG_INSTALL_DIR)/etc/netifyd/interfaces.d/* $(1)/etc/netifyd/interfaces.d
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
