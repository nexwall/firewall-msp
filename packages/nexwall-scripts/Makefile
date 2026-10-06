#
# Copyright (C) 2026 Nexwall
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nexwall-scripts
PKG_VERSION:=1.0.0
PKG_RELEASE:=7

PKG_MAINTAINER:=Nexwall
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define Package/nexwall-scripts
	SECTION:=base
	CATEGORY:=Nexwall
	TITLE:=Nexwall operator/support diagnostic tools
	DEPENDS:=+nftables +conntrack +gawk +socat +curl +ethtool +python3-light +openssl-util +python3-cryptodome
	PKGARCH:=all
endef

define Package/nexwall-scripts/description
	Live nftables rule/NAT tracers for diagnosing firewall behavior: fwtrace
	(per-flow decisions for routed/NAT'd traffic, with conntrack-based NAT
	correlation) and drppkt (also the local input chain, with the full rule
	path). Each decision comes with the rule's name and the reason (firewall
	rule, zone policy, DPI, IP & Geo Blocking). Non-invasive (observe only,
	never drop/reject/accept), validated input, self-cleaning.
	Also nfq-watchdog (recovers the DPI/IPS engines when a kernel packet queue stops
	being served, with report, alert and restart limits) and dpidbg (look inside the
	DPI engine: status, unclassified traffic, debug capture, loaded catalog).
	Also nexwall-fastpath (hands connections the DPI and IPS engines are finished with to the kernel's
	flow table; on by default, see /etc/config/nexwall_perf).
	See nexwall-scripts (github.com/nexwall/nexwall-scripts) for full docs.
endef

define Build/Compile
endef

define Package/nexwall-scripts/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/drppkt $(1)/usr/sbin/drppkt
	$(INSTALL_BIN) ./files/fwtrace $(1)/usr/sbin/fwtrace
	$(INSTALL_BIN) ./files/nfq-watchdog $(1)/usr/sbin/nexwall-nfq-watchdog
	$(INSTALL_BIN) ./files/dpidbg $(1)/usr/sbin/dpidbg
	$(INSTALL_BIN) ./files/nexwall-fastpath $(1)/usr/sbin/nexwall-fastpath
	$(INSTALL_BIN) ./files/nexwall-secure-defaults $(1)/usr/sbin/nexwall-secure-defaults
	$(INSTALL_BIN) ./files/nexwall-webui-cert $(1)/usr/sbin/nexwall-webui-cert
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/nexwall-fastpath.init $(1)/etc/init.d/nexwall-fastpath
	$(INSTALL_BIN) ./files/nexwall-secure-defaults.init $(1)/etc/init.d/nexwall-secure-defaults
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/uci-defaults/99-nexwall-nfq-watchdog $(1)/etc/uci-defaults/99-nexwall-nfq-watchdog
	$(INSTALL_BIN) ./files/uci-defaults/99-nexwall-perf $(1)/etc/uci-defaults/99-nexwall-perf
	$(INSTALL_BIN) ./files/uci-defaults/99-nexwall-secure-defaults $(1)/etc/uci-defaults/99-nexwall-secure-defaults
	$(INSTALL_BIN) ./files/uci-defaults/99-nexwall-dns-log $(1)/etc/uci-defaults/99-nexwall-dns-log
	$(INSTALL_BIN) ./files/uci-defaults/99-nexwall-webui-cert $(1)/etc/uci-defaults/99-nexwall-webui-cert
	$(INSTALL_BIN) ./files/uci-defaults/99-nexwall-webui-redirect $(1)/etc/uci-defaults/99-nexwall-webui-redirect
	$(INSTALL_DIR) $(1)/usr/share/nexwall/redirect
	$(INSTALL_DATA) ./files/redirect/index.html $(1)/usr/share/nexwall/redirect/index.html
	$(INSTALL_DIR) $(1)/usr/lib/nexwall-scripts
	$(INSTALL_DATA) ./files/lib/trace.awk $(1)/usr/lib/nexwall-scripts/trace.awk
	$(INSTALL_DATA) ./files/lib/common.sh $(1)/usr/lib/nexwall-scripts/common.sh
endef

$(eval $(call BuildPackage,nexwall-scripts))
