#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#
# (this recipe only; the package it installs is proprietary, see below)

include $(TOPDIR)/rules.mk

PKG_NAME:=nexwall-webprotection
# Web Protection (category based web filtering) is built in a private repository and published, signed, to the Nexwall
# vendor feed. This recipe downloads one pinned build and checks its SHA-256, so the public tree does not carry that code.
# To ship a new version: release it (scripts/release-feed.sh in the private repository), then bump WP_FEED_VERSION and
# WP_FEED_SHA256 here and PKG_RELEASE.
PKG_VERSION:=0.5.3
PKG_RELEASE:=5

WP_FEED_VERSION:=0.7.2
WP_FEED_SHA256:=41ebab92f6621b97ecf874e7ce6b354bb15a46e449542e757bc02b31c57a3f8f
WP_FEED:=https://updates.nexwall.com.br/vendor/stable

PKG_SOURCE:=nexwall-webprotection_$(WP_FEED_VERSION)_all.tar.gz
PKG_SOURCE_URL:=$(WP_FEED)/all
PKG_HASH:=$(WP_FEED_SHA256)

PKG_MAINTAINER:=Nexwall
PKG_LICENSE:=Proprietary

include $(INCLUDE_DIR)/package.mk

define Package/nexwall-webprotection
	SECTION:=base
	CATEGORY:=Nexwall
	TITLE:=Web Protection
	DEPENDS:= \
		+ns-api \
		+ns-dpi \
		+python3 \
		+python3-nethsec \
		+python3-requests \
		+python3-cryptodome \
		+squid \
		+openssl-util \
		+ca-bundle \
		+nexwall-webd \
		+clamav \
		+freshclam \
		+yara
	PKGARCH:=all
endef

define Package/nexwall-webprotection/description
Web Protection: category based web filtering enforced by the DPI engine (proprietary, downloaded from the Nexwall vendor feed)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/root
	tar -C $(PKG_BUILD_DIR)/root -xzf $(DL_DIR)/$(PKG_SOURCE)
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/nexwall-webprotection/conffiles
/etc/config/web_protection
endef

define Package/nexwall-webprotection/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
  [ -x /etc/uci-defaults/99-web-protection-defaults ] && /etc/uci-defaults/99-web-protection-defaults && rm -f /etc/uci-defaults/99-web-protection-defaults
  /etc/init.d/cron restart
  /etc/init.d/rpcd restart
  /etc/init.d/nexwall-web-inspect enable
fi
exit 0
endef

define Package/nexwall-webprotection/install
	$(CP) $(PKG_BUILD_DIR)/root/. $(1)/
	rm -f $(1)/usr/share/nexwall-webprotection.build
endef

$(eval $(call BuildPackage,nexwall-webprotection))
