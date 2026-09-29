#
# Copyright (C) 2026 Nexwall
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nexwall-scripts
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Nexwall
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define Package/nexwall-scripts
	SECTION:=base
	CATEGORY:=Nexwall
	TITLE:=Nexwall operator/support diagnostic tools
	DEPENDS:=+nftables +conntrack-tools
	PKGARCH:=all
endef

define Package/nexwall-scripts/description
	Live nftables rule/NAT tracers for diagnosing firewall behavior: drppkt
	(per-packet trace including the local input chain) and fwtrace (per-flow,
	routed/NAT'd traffic only, with conntrack-based NAT correlation). Both are
	non-invasive (observe only, never drop/reject/accept) and self-cleaning.
	See nexwall-scripts (github.com/nexwall/nexwall-scripts) for full docs.
endef

define Build/Compile
endef

define Package/nexwall-scripts/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/drppkt $(1)/usr/sbin/drppkt
	$(INSTALL_BIN) ./files/fwtrace $(1)/usr/sbin/fwtrace
endef

$(eval $(call BuildPackage,nexwall-scripts))
