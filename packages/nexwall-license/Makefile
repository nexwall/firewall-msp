#
# Copyright (C) 2026 Nexwall
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nexwall-license
PKG_VERSION:=1.1.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Nexwall
PKG_LICENSE:=GPL-2.0-only

# The license core (licensing decisions, check-in with the license server, enforcement, self-update) is a vendor
# binary: built from a private repository and published, signed, to the Nexwall vendor feed. This recipe does not
# contain it; it downloads one pinned version at build time and checks its SHA-256, so the public build is
# reproducible and a changed file on the feed is refused. Without it (option off, other architecture, feed not
# reachable by the builder) the image is a community build: no licensing logic is shipped and the unit runs with
# the limited feature set. See nexwall-internal/msp/LICENSE_PROTECTION_ARCHITECTURE.md.
VENDOR_CORE_VERSION:=1.4.0
VENDOR_CORE_SHA256:=383c8c96d068bbeeae153b9c37601141773dc10213765452069d9eedb2a68094
VENDOR_FEED:=https://updates.nexwall.com.br/vendor/stable

ifeq ($(CONFIG_NEXWALL_LICENSE_VENDOR_CORE),y)
ifeq ($(ARCH),x86_64)
PKG_SOURCE:=nexwall-license-core_$(VENDOR_CORE_VERSION)_x86_64.tar.gz
PKG_SOURCE_URL:=$(VENDOR_FEED)/x86_64
PKG_HASH:=$(VENDOR_CORE_SHA256)
endif
endif

include $(INCLUDE_DIR)/package.mk

define Package/nexwall-license
	SECTION:=base
	CATEGORY:=Nexwall
	TITLE:=Nexwall license
	DEPENDS:=+ca-bundle
	PKGARCH:=$(if $(CONFIG_NEXWALL_LICENSE_VENDOR_CORE),$(ARCH),all)
endef

define Package/nexwall-license/config
	config NEXWALL_LICENSE_VENDOR_CORE
		bool "Include the Nexwall license core (vendor binary from the Nexwall vendor feed)"
		depends on PACKAGE_nexwall-license
		default y
		help
		  Without it the image is a community build: no licensing logic is included and the
		  unit runs with the limited feature set.
endef

define Package/nexwall-license/description
	Starts the Nexwall license core when it is installed (it registers this firewall with the license
	server, keeps the signed license current and applies the entitlements) and keeps the unit's license
	identity across upgrades.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	if [ -n "$(PKG_SOURCE)" ]; then tar -C $(PKG_BUILD_DIR) -xzf $(DL_DIR)/$(PKG_SOURCE); fi
endef

define Build/Compile
endef

define Package/nexwall-license/install
	if [ -f $(PKG_BUILD_DIR)/nexwall-licensed ]; then \
		$(INSTALL_DIR) $(1)/usr/sbin; \
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/nexwall-licensed $(1)/usr/sbin/nexwall-licensed; \
		for n in licensectl nexwall-license-register nexwall-license-enforce nexwall-serial; do \
			$(LN) nexwall-licensed $(1)/usr/sbin/$$$$n; \
		done; \
	fi

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/nexwall-license.init $(1)/etc/init.d/nexwall-license

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/nexwall-license.config $(1)/etc/config/nexwall-license

	# kept across image upgrades: without hwid/serial/device_token/device.key the unit would re-register as a NEW
	# device on every upgrade (exhausting the customer's firewall_limit), and an assigned unit that lost its device
	# key is refused by the server until an administrator clears it
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_CONF) ./files/nexwall-license.keep $(1)/lib/upgrade/keep.d/nexwall-license

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/nexwall-license-cron $(1)/etc/uci-defaults/99-nexwall-license-cron
endef

$(eval $(call BuildPackage,nexwall-license))
