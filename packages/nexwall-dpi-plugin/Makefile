#
# Copyright (C) 2026 Nexwall
#
# This is free software, licensed under the GNU General Public License v2 (this recipe only).
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nexwall-dpi-plugin
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Nexwall

# The DPI enforcement plugin (nx-proc-flow-actions) is proprietary: built in a private pipeline against exactly the
# netifyd package of this tree and published, signed, to the Nexwall vendor feed. This recipe downloads one pinned
# build and checks its SHA-256 and that it was built for this netifyd release (the plugin links against libnetifyd,
# so a mismatch is refused at build time). The plugin only applies actions while the Nexwall license core hands it a
# valid short-lived token; without the plugin (community build) the engine still classifies traffic but nothing is
# blocked or marked. See nexwall-internal/msp/DPI_PLUGIN_LICENSE_TOKEN.md.
PLUGIN_FEED_VERSION:=1.0.0
PLUGIN_FEED_SHA256:=PLACEHOLDER_UNTIL_PUBLISHED
PLUGIN_FEED:=https://updates.nexwall.com.br/vendor/stable

NETIFYD_ABI:=$(shell sed -n 's/^PKG_VERSION:=//p' $(CURDIR)/../netifyd/Makefile)-r$(shell sed -n 's/^PKG_RELEASE:=//p' $(CURDIR)/../netifyd/Makefile)

ifeq ($(CONFIG_NEXWALL_DPI_PLUGIN_VENDOR),y)
ifeq ($(ARCH),x86_64)
PKG_SOURCE:=nexwall-dpi-plugin_$(PLUGIN_FEED_VERSION)_x86_64.tar.gz
PKG_SOURCE_URL:=$(PLUGIN_FEED)/x86_64
PKG_HASH:=$(PLUGIN_FEED_SHA256)
endif
endif

include $(INCLUDE_DIR)/package.mk

define Package/nexwall-dpi-plugin
	SECTION:=admin
	CATEGORY:=Nexwall
	TITLE:=Nexwall DPI enforcement plugin
	DEPENDS:=+netifyd +libnetfilter-conntrack +libgcrypt +nexwall-license
	PKGARCH:=$(if $(CONFIG_NEXWALL_DPI_PLUGIN_VENDOR),$(ARCH),all)
endef

define Package/nexwall-dpi-plugin/config
	config NEXWALL_DPI_PLUGIN_VENDOR
		bool "Include the Nexwall DPI enforcement plugin (vendor binary from the Nexwall vendor feed)"
		depends on PACKAGE_nexwall-dpi-plugin
		default y
		help
		  Without it the traffic classification engine still runs but no DPI rule is enforced.
endef

define Package/nexwall-dpi-plugin/description
	Enforces the application control (DPI) rules: marks or blocks classified flows through conntrack labels
	while the Nexwall license core confirms the unit is licensed.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	if [ -n "$(PKG_SOURCE)" ]; then \
		tar -C $(PKG_BUILD_DIR) -xzf $(DL_DIR)/$(PKG_SOURCE); \
		grep -qx "netifyd=$(NETIFYD_ABI)" $(PKG_BUILD_DIR)/BUILD_INFO || { \
			echo "nexwall-dpi-plugin: the pinned plugin was not built for netifyd $(NETIFYD_ABI): publish a matching plugin and update PLUGIN_FEED_VERSION and PLUGIN_FEED_SHA256" >&2; \
			exit 1; }; \
	fi
endef

define Build/Compile
endef

define Package/nexwall-dpi-plugin/install
	if [ -f $(PKG_BUILD_DIR)/libnx-proc-flow-actions.so ]; then \
		$(INSTALL_DIR) $(1)/usr/lib $(1)/etc/netifyd/plugins.d; \
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/libnx-proc-flow-actions.so $(1)/usr/lib/libnx-proc-flow-actions.so; \
		$(INSTALL_DATA) $(PKG_BUILD_DIR)/10-dpi-actions.conf $(1)/etc/netifyd/plugins.d/10-dpi-actions.conf; \
	fi
endef

$(eval $(call BuildPackage,nexwall-dpi-plugin))
