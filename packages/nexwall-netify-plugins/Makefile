#
# Copyright (C) 2026 Nexwall
#
# This is free software, licensed under the GNU General Public License v2 (this recipe only).
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nexwall-netify-plugins
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Nexwall

# The traffic-engine plugins (nx-proc-flow-actions, nx-proc-aggregator, nx-sink-log, nx-proc-flows, nx-sink-http)
# are proprietary: built in a private pipeline against exactly the netifyd package of this tree and published,
# signed, to the Nexwall vendor feed. This recipe downloads one pinned
# build and checks its SHA-256 and that it was built for this netifyd release (the plugin links against libnetifyd,
# so a mismatch is refused at build time). The enforcement and statistics plugins act only while the Nexwall license
# core hands them a valid short-lived token. Without the package (community build) the engine still classifies
# traffic but nothing is blocked, accounted or exported. See nexwall-internal/msp/DPI_PLUGIN_LICENSE_TOKEN.md.
PLUGIN_FEED_VERSION:=1.0.1
PLUGIN_FEED_SHA256:=23a86ff53d3bfddf7018aefa72469f5727ef53c604dcce8d081e6a9a13ff37a3
PLUGIN_FEED:=https://updates.nexwall.com.br/vendor/stable

NETIFYD_ABI:=$(shell sed -n 's/^PKG_VERSION:=//p' $(CURDIR)/../netifyd/Makefile)-r$(shell sed -n 's/^PKG_RELEASE:=//p' $(CURDIR)/../netifyd/Makefile)

ifeq ($(CONFIG_NEXWALL_NETIFY_PLUGINS_VENDOR),y)
ifeq ($(ARCH),x86_64)
PKG_SOURCE:=nexwall-netify-plugins_$(PLUGIN_FEED_VERSION)_x86_64.tar.gz
PKG_SOURCE_URL:=$(PLUGIN_FEED)/x86_64
PKG_HASH:=$(PLUGIN_FEED_SHA256)
endif
endif

include $(INCLUDE_DIR)/package.mk

define Package/nexwall-netify-plugins
	SECTION:=admin
	CATEGORY:=Nexwall
	TITLE:=Nexwall traffic engine plugins
	DEPENDS:=+netifyd +libnetfilter-conntrack +libgcrypt +nexwall-license
	PKGARCH:=$(if $(CONFIG_NEXWALL_NETIFY_PLUGINS_VENDOR),$(ARCH),all)
endef

define Package/nexwall-netify-plugins/config
	config NEXWALL_NETIFY_PLUGINS_VENDOR
		bool "Include the Nexwall traffic engine plugins (vendor binaries from the Nexwall vendor feed)"
		depends on PACKAGE_nexwall-netify-plugins
		default y
		help
		  Without them the traffic classification engine still runs but no DPI rule is enforced and no statistics or flows are exported.
endef

define Package/nexwall-netify-plugins/description
	DPI rule enforcement, traffic accounting ("top consumers", statistics), live flows and the HTTP sink for the
	traffic classification engine. The enforcement and accounting plugins run while the Nexwall license core
	confirms the unit is licensed.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	if [ -n "$(PKG_SOURCE)" ]; then \
		tar -C $(PKG_BUILD_DIR) -xzf $(DL_DIR)/$(PKG_SOURCE); \
		grep -qx "netifyd=$(NETIFYD_ABI)" $(PKG_BUILD_DIR)/BUILD_INFO || { \
			echo "nexwall-netify-plugins: the pinned plugin was not built for netifyd $(NETIFYD_ABI): publish a matching plugin and update PLUGIN_FEED_VERSION and PLUGIN_FEED_SHA256" >&2; \
			exit 1; }; \
	fi
endef

define Build/Compile
endef

define Package/nexwall-netify-plugins/install
	if [ -d $(PKG_BUILD_DIR)/usr/lib ]; then \
		$(INSTALL_DIR) $(1)/usr/lib $(1)/etc/netifyd/plugins.d; \
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/lib/libnx-*.so $(1)/usr/lib/; \
		$(INSTALL_DATA) $(PKG_BUILD_DIR)/etc/netifyd/plugins.d/*.conf $(1)/etc/netifyd/plugins.d/; \
	fi
endef

$(eval $(call BuildPackage,nexwall-netify-plugins))
