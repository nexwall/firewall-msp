#
# Copyright (C) 2026 Nexwall
#
# This is free software, licensed under the GNU General Public License v2 (this recipe only).
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nexwall-webd
PKG_VERSION:=1.1.1
PKG_RELEASE:=3

PKG_MAINTAINER:=Nexwall

# nexwall-webd is the proprietary binary of Web Protection (the antivirus scanning service, its ICAP front for Squid and
# the SSL-inspection guard). It is built in a private repository (scripts/release-feed.sh) and published, signed, to the
# Nexwall vendor feed; this recipe downloads one pinned build and checks its SHA-256. It acts only while the Nexwall
# license core hands it a valid short-lived feature token (scopes `av` and `web`, core 1.7.0 or later). Without the
# package (community build) Squid runs but nothing is redirected to it and nothing is scanned.
# See nexwall-internal/msp/WEB_PROTECTION.md and the license token notes (DPI_PLUGIN_LICENSE_TOKEN.md).
WEBD_FEED_VERSION:=1.3.0
WEBD_FEED_SHA256:=8d01e8d543446f21f7b6e4c555b5169f4424bd5c0960ee2410a1758fcd21b346
WEBD_FEED:=https://updates.nexwall.com.br/vendor/stable

ifeq ($(CONFIG_NEXWALL_WEBD_VENDOR),y)
ifeq ($(ARCH),x86_64)
PKG_SOURCE:=nexwall-webd_$(WEBD_FEED_VERSION)_x86_64.tar.gz
PKG_SOURCE_URL:=$(WEBD_FEED)/x86_64
PKG_HASH:=$(WEBD_FEED_SHA256)
endif
endif

include $(INCLUDE_DIR)/package.mk

define Package/nexwall-webd
	SECTION:=admin
	CATEGORY:=Nexwall
	TITLE:=Web Protection service binary
	DEPENDS:=+nexwall-license
	PKGARCH:=$(if $(CONFIG_NEXWALL_WEBD_VENDOR),$(ARCH),all)
endef

define Package/nexwall-webd/config
	config NEXWALL_WEBD_VENDOR
		bool "Include the Web Protection service binary (vendor binary from the Nexwall vendor feed)"
		depends on PACKAGE_nexwall-webd
		default y
		help
		  Without it Squid runs but no connection is redirected to it and no download is scanned.
endef

define Package/nexwall-webd/description
	Antivirus scanning service, ICAP front for Squid and SSL-inspection guard of Web Protection. They run while the
	Nexwall license core confirms the unit is licensed.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	if [ -n "$(PKG_SOURCE)" ]; then \
		tar -C $(PKG_BUILD_DIR) -xzf $(DL_DIR)/$(PKG_SOURCE); \
	fi
endef

define Build/Compile
endef

define Package/nexwall-webd/install
	if [ -f $(PKG_BUILD_DIR)/usr/sbin/nexwall-webd ]; then \
		$(INSTALL_DIR) $(1)/usr/sbin; \
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/sbin/nexwall-webd $(1)/usr/sbin/; \
	fi
endef

$(eval $(call BuildPackage,nexwall-webd))
