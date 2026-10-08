#
# Copyright (C) 2022 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

include $(TOPDIR)/rules.mk
 
PKG_NAME:=ns-ui
# The web UI is built in a private repository and published, signed, to the Nexwall vendor feed. This recipe
# downloads one pinned build and checks its SHA-256, so the public tree needs no access to that repository.
# PKG_VERSION stays at the upstream-derived 2.24.1 so package upgrades keep ordering correctly; the feed build is
# UI_FEED_VERSION. To ship a new UI: release it (scripts/release-feed.sh in the UI repository), then bump
# UI_FEED_VERSION and UI_FEED_SHA256 here and PKG_RELEASE.
PKG_VERSION:=2.24.1
PKG_RELEASE:=37

UI_FEED_VERSION:=2.0.2
UI_FEED_SHA256:=73a50111c3f61989032baeecbd008b9c93268b1bf1b668eb23b5b5482358252e
UI_FEED:=https://updates.nexwall.com.br/vendor/stable

PKG_SOURCE:=nexwall-ui_$(UI_FEED_VERSION)_all.tar.gz
PKG_SOURCE_URL:=$(UI_FEED)/all
PKG_HASH:=$(UI_FEED_SHA256)

PKG_MAINTAINER:=Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
PKG_LICENSE:=GPL-3.0-only

include $(INCLUDE_DIR)/package.mk

define Package/ns-ui
	SECTION:=base
	CATEGORY:=Nexwall
	TITLE:=Nexwall Firewall UI
	DEPENDS:=+nginx-ssl
	PKGARCH:=all
endef

define Package/ns-ui/description
Nexwall Firewall web user interface
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/dist
	tar -C $(PKG_BUILD_DIR)/dist -xzf $(DL_DIR)/$(PKG_SOURCE)
endef

define Build/Configure
endef

define Package/ns-ui/conffiles
/etc/config/ns-ui
/www-ns/branding.js
endef

define Build/Compile
endef

define Package/ns-ui/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
  /etc/init.d/ns-ui restart
fi
exit 0
endef

define Package/ns-ui/install
	$(INSTALL_DIR) $(1)/www-ns
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_CONF) ./files/config $(1)/etc/config/ns-ui
	$(INSTALL_BIN) ./files/ns-ui $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/ns-ui.init $(1)/etc/init.d/ns-ui
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/ns-ui.uci-defaults $(1)/etc/uci-defaults
	$(CP) $(PKG_BUILD_DIR)/dist/* $(1)/www-ns
	rm -f $(1)/www-ns/BUILD_INFO
endef
 
$(eval $(call BuildPackage,ns-ui))
