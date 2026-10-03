#
# Copyright (C) 2026 Nexwall
#
# This is free software, licensed under the GNU General Public License v2 (this recipe only).
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nexwall-snort-plugins
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Nexwall

# The Snort 3 license gate (nx_ips_gate) is proprietary: built in a private pipeline against exactly the snort3 package of
# this tree and published, signed, to the Nexwall vendor feed. This recipe downloads one pinned build and checks its SHA-256
# and that it was built for this snort3 release (a Snort plugin is tied to the engine it was built against). The IPS detects
# only while the Nexwall license core hands the plugin a valid short-lived token. Without the package (community build) snort
# runs ungated, but the managed signatures and the license-checked API are not there either.
# See nexwall-internal/msp/IPS_PLUGIN_AND_SIGNATURES.md.
PLUGIN_FEED_VERSION:=1.0.1
PLUGIN_FEED_SHA256:=54290609e9a704165a07d768b633f06db885fe3016ceb4b157856a53bf50bfc1
PLUGIN_FEED:=https://updates.nexwall.com.br/vendor/stable

SNORT_ABI:=$(shell sed -n 's/^PKG_VERSION:=//p' $(CURDIR)/../snort3/Makefile)-r$(shell sed -n 's/^PKG_RELEASE:=//p' $(CURDIR)/../snort3/Makefile)

ifeq ($(CONFIG_NEXWALL_SNORT_PLUGINS_VENDOR),y)
ifeq ($(ARCH),x86_64)
PKG_SOURCE:=nexwall-snort-plugins_$(PLUGIN_FEED_VERSION)_x86_64.tar.gz
PKG_SOURCE_URL:=$(PLUGIN_FEED)/x86_64
PKG_HASH:=$(PLUGIN_FEED_SHA256)
endif
endif

include $(INCLUDE_DIR)/package.mk

define Package/nexwall-snort-plugins
	SECTION:=net
	CATEGORY:=Nexwall
	TITLE:=Nexwall IPS license gate
	DEPENDS:=+snort3 +libgcrypt +nexwall-license
	PKGARCH:=$(if $(CONFIG_NEXWALL_SNORT_PLUGINS_VENDOR),$(ARCH),all)
endef

define Package/nexwall-snort-plugins/config
	config NEXWALL_SNORT_PLUGINS_VENDOR
		bool "Include the Nexwall IPS license gate (vendor binary from the Nexwall vendor feed)"
		depends on PACKAGE_nexwall-snort-plugins
		default y
		help
		  Without it snort runs without the license gate.
endef

define Package/nexwall-snort-plugins/description
	Snort 3 plugin that lets the IPS inspect traffic only while the Nexwall license core confirms the unit is licensed.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	if [ -n "$(PKG_SOURCE)" ]; then \
		tar -C $(PKG_BUILD_DIR) -xzf $(DL_DIR)/$(PKG_SOURCE); \
		grep -qx "snort3=$(SNORT_ABI)" $(PKG_BUILD_DIR)/BUILD_INFO || { \
			echo "nexwall-snort-plugins: the pinned plugin was not built for snort3 $(SNORT_ABI): publish a matching plugin and update PLUGIN_FEED_VERSION and PLUGIN_FEED_SHA256" >&2; \
			exit 1; }; \
	fi
endef

define Build/Compile
endef

define Package/nexwall-snort-plugins/install
	if [ -f $(PKG_BUILD_DIR)/usr/lib/snort_nexwall/nx_ips_gate.so ]; then \
		$(INSTALL_DIR) $(1)/usr/lib/snort_nexwall; \
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/lib/snort_nexwall/nx_ips_gate.so $(1)/usr/lib/snort_nexwall/; \
	fi
endef

$(eval $(call BuildPackage,nexwall-snort-plugins))
