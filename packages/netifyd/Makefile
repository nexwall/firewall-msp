include $(TOPDIR)/rules.mk

PKG_NAME:=netifyd
PKG_VERSION:=5.2.8
PKG_RELEASE:=1
PKG_MAINTAINER:=Nexwall <dev@nexwall.com.br>
PKG_LICENSE:=GPL-3.0-or-later

PKG_BUILD_PARALLEL:=1
PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

# Open source Netify Agent (GPL), built from the vendor source at the tag v5.2.8-1.
# This is the same major version the original design used (inline NFQUEUE capture,
# native plugin loading), unlike the earlier Nexwall build of this package which
# used the community v4.4.7 (passive capture, no plugin loader). The vendor ships
# an OpenWrt package template at deploy/openwrt/ in this same source tree; this
# Makefile mirrors it (deploy/openwrt/Makefile.in), translated to concrete values.
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://gitlab.com/netify.ai/public/netify-agent.git
PKG_SOURCE_VERSION:=19458098898353ed1950cbdd35c85ee79c70a204
PKG_MIRROR_HASH:=skip

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
		+zoneinfo-core
endef

define Package/netifyd/description
The Netify Agent is a deep-packet inspection engine built on nDPI. It detects
network protocols and applications inline (NFQUEUE capture) and streams the
detections as JSON events, and can load plugins to act on them. Application
names come from the open signature list installed with the package; the
proprietary Nexwall plugins (see ns-dpi) add rule-based blocking, QoS marking
and traffic analytics.
endef

define Package/netifyd/conffiles
/etc/netifyd.conf
/etc/config/netifyd
/etc/netifyd/agent.uuid
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
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/netifyd $(1)/usr/sbin
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
