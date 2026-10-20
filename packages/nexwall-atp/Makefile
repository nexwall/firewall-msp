#
# Copyright (C) 2026 Nexwall
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nexwall-atp
PKG_VERSION:=0.3.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Nexwall
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define Package/nexwall-atp
	SECTION:=base
	CATEGORY:=Nexwall
	TITLE:=Advanced Threat Protection: flow scorer
	DEPENDS:=+python3-light +python3-ctypes +python3-cryptodome +python3-nethsec
	PKGARCH:=all
endef

define Package/nexwall-atp/description
	Scores the hosts of the inner networks against a behaviour model, from the flows the DPI engine
	already keeps and the DNS names they ask. Advisory events only: nothing is blocked. The modules
	under /usr/lib/nexwall-atp are copied from github.com/nexwall/nexwall-atp (sync-from-atp.sh).
endef

define Package/nexwall-atp/conffiles
/etc/config/nexwall_atp
endef

define Build/Compile
endef

define Package/nexwall-atp/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) ./files/nexwall-atp $(1)/usr/sbin/nexwall-atp
	$(INSTALL_BIN) ./files/nexwall-atp.init $(1)/etc/init.d/nexwall-atp
	$(INSTALL_CONF) ./files/nexwall_atp.config $(1)/etc/config/nexwall_atp
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/99-nexwall-atp.uci-defaults $(1)/etc/uci-defaults/99-nexwall-atp
	$(INSTALL_DIR) $(1)/usr/lib/nexwall-atp
	$(CP) ./files/lib/atp $(1)/usr/lib/nexwall-atp/
endef

define Package/nexwall-atp/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || /etc/init.d/nexwall-atp enable
exit 0
endef

$(eval $(call BuildPackage,nexwall-atp))
