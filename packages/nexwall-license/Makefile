#
# Copyright (C) 2026 Nexwall
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nexwall-license
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Nexwall
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define Package/nexwall-license
	SECTION:=base
	CATEGORY:=Nexwall
	TITLE:=Nexwall license client
	DEPENDS:= \
		+python3 \
		+python3-requests \
		+python3-cryptodome
	PKGARCH:=all
endef

define Package/nexwall-license/description
	Registers this firewall against license.nexwall.com.br and keeps a
	locally stored, cryptographically verified license current, for other
	packages to read when deciding which features a subscription enables.
endef

define Build/Compile
endef

define Package/nexwall-license/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/nexwall-license-register $(1)/usr/sbin/nexwall-license-register

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/nexwall-license.config $(1)/etc/config/nexwall-license

	$(INSTALL_DIR) $(1)/etc/nexwall-license
	$(INSTALL_DATA) ./files/pubkey.pem $(1)/etc/nexwall-license/pubkey.pem

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/nexwall-license-cron $(1)/etc/uci-defaults/99-nexwall-license-cron
endef

$(eval $(call BuildPackage,nexwall-license))
