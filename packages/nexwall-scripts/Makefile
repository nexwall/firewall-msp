#
# Copyright (C) 2026 Nexwall
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nexwall-scripts
PKG_VERSION:=1.0.0
PKG_RELEASE:=2

PKG_MAINTAINER:=Nexwall
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define Package/nexwall-scripts
	SECTION:=base
	CATEGORY:=Nexwall
	TITLE:=Nexwall operator/support diagnostic tools
	DEPENDS:=+nftables +conntrack-tools +gawk
	PKGARCH:=all
endef

define Package/nexwall-scripts/description
	Live nftables rule/NAT tracers for diagnosing firewall behavior: fwtrace
	(per-flow decisions for routed/NAT'd traffic, with conntrack-based NAT
	correlation) and drppkt (also the local input chain, with the full rule
	path). Each decision comes with the rule's name and the reason (firewall
	rule, zone policy, DPI, IP & Geo Blocking). Non-invasive (observe only,
	never drop/reject/accept), validated input, self-cleaning.
	See nexwall-scripts (github.com/nexwall/nexwall-scripts) for full docs.
endef

define Build/Compile
endef

define Package/nexwall-scripts/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/drppkt $(1)/usr/sbin/drppkt
	$(INSTALL_BIN) ./files/fwtrace $(1)/usr/sbin/fwtrace
	$(INSTALL_DIR) $(1)/usr/lib/nexwall-scripts
	$(INSTALL_DATA) ./files/lib/trace.awk $(1)/usr/lib/nexwall-scripts/trace.awk
	$(INSTALL_DATA) ./files/lib/common.sh $(1)/usr/lib/nexwall-scripts/common.sh
endef

$(eval $(call BuildPackage,nexwall-scripts))
