#
# Copyright (C) 2022 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

include $(TOPDIR)/rules.mk
 
PKG_NAME:=ns-ui
# Nexwall fork of NethServer/nethsecurity-ui (upstream 2.24.1), pinned to a commit.
# Bump PKG_SOURCE_VERSION (and PKG_RELEASE) to ship a new UI build.
PKG_VERSION:=2.24.1
PKG_RELEASE:=2

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/nexwall/nexwall-ui.git
PKG_SOURCE_VERSION:=88ef6ec7c55def37cb439cd17e817935334c858f
PKG_SOURCE_SUBDIR:=nexwall-ui-$(PKG_VERSION)
# tarball name tied to the commit, so a cached upstream tarball is never reused
PKG_SOURCE:=nexwall-ui-$(PKG_SOURCE_VERSION).tar.zst
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)
PKG_MIRROR_HASH:=skip

PKG_MAINTAINER:=Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
PKG_LICENSE:=GPL-3.0-only

PKG_BUILD_DEPENDS:=node/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/ns-ui
	SECTION:=base
	CATEGORY:=Nexwall
	TITLE:=Nexwall Firewall UI
	URL:=https://github.com/nexwall/nexwall-ui/
	DEPENDS:=+nginx-ssl
	PKGARCH:=all
endef

define Package/ns-ui/description
Nexwall Firewall web user interface
endef

define Build/Configure
endef

define Package/ns-ui/conffiles
/etc/config/ns-ui
/www-ns/branding.js
endef

define Build/Compile
	(cd $(PKG_BUILD_DIR) && npm ci && npm run build)
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
endef
 
$(eval $(call BuildPackage,ns-ui))
