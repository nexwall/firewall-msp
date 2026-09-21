include $(TOPDIR)/rules.mk

PKG_NAME:=netifyd
PKG_VERSION:=4.4.7
PKG_RELEASE:=1
PKG_MAINTAINER:=Nexwall <dev@nexwall.com.br>
PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_PARALLEL:=1
PKG_FIXUP:=autoreconf
PKG_INSTALL:=1
PKG_BUILD_FLAGS:=gc-sections

# Open source Netify Agent (GPL), built from the vendor source at the tag v4.4.7
# (same version as the package in the OpenWrt packages feed). The source pulls its
# libraries (nDPI and others) as git submodules.
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://gitlab.com/netify.ai/public/netify-agent.git
PKG_SOURCE_VERSION:=4d8d92104e694db3115a1615106022fc28aaed0f
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
		+kmod-ipt-conntrack-label \
		+kmod-ipt-ipset \
		+libatomic \
		+libblobmsg-json \
		+libc \
		+libcap \
		+libcurl \
		+libgcrypt \
		+libgpg-error \
		+libipset \
		+libjson-c \
		+libmnl \
		+libnetfilter-conntrack \
		+libnetfilter-queue \
		+libopenssl \
		+libpcap \
		+libpthread \
		+libstdcpp \
		+libubox \
		+libubus \
		+libuci \
		+nftables \
		+zlib \
		+zoneinfo-core
endef

define Package/netifyd/description
The Netify Agent is a deep-packet inspection engine built on nDPI. It detects
network protocols and applications, and streams the detections as JSON events.
Application names come from the open signature list installed with the package.
endef

define Package/netifyd/conffiles
/etc/netifyd.conf
/etc/config/netifyd
/etc/netifyd/agent.uuid
endef

TARGET_CFLAGS+=-Wno-psabi
TARGET_CXXFLAGS+=-std=c++11 -Wno-psabi

# libndpi.a is static and was built with libgcrypt (QUIC decryption), so the agent
# link must pull libgcrypt and libgpg-error in explicitly.
TARGET_LDFLAGS+=-lgcrypt -lgpg-error

CONFIGURE_ARGS+= \
	--disable-shared \
	--without-local-libgcrypt \
	--sharedstatedir=/var/run \
	--enable-lean-and-mean \
	--disable-libtcmalloc \
	--disable-jemalloc \
	--without-systemdsystemunitdir \
	--without-tmpfilesdir \
	--disable-inotify

ifneq ($(CONFIG_LIBCURL_ZLIB),y)
CONFIGURE_ARGS+= --without-libcurl-zlib
endif

define Package/netifyd/install
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/netifyd
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/share/netifyd
	$(INSTALL_DATA) ./files/netifyd.conf $(1)/etc/netifyd.conf
	$(INSTALL_CONF) ./files/netifyd.config $(1)/etc/config/netifyd
	$(INSTALL_BIN) ./files/netifyd.init $(1)/etc/init.d/netifyd
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/netifyd $(1)/usr/sbin/netifyd
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/deploy/netify-apps.conf $(1)/etc/netifyd/netify-apps.conf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/deploy/netify-categories.json $(1)/etc/netifyd/netify-categories.json
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/deploy/functions.sh $(1)/usr/share/netifyd/functions.sh
	# the agent reads its data under /etc/netify.d, the rest of the system uses /etc/netifyd
	$(LN) netifyd $(1)/etc/netify.d
endef

$(eval $(call BuildPackage,netifyd))
