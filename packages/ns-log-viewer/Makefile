#
# Copyright (C) 2026 Nexwall
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ns-log-viewer
PKG_VERSION:=1.0.0
PKG_RELEASE:=2

PKG_MAINTAINER:=Nexwall
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define Package/ns-log-viewer
	SECTION:=base
	CATEGORY:=Nexwall
	TITLE:=Nexwall Log Viewer
	DEPENDS:=+victoria-logs +rsyslog
	PKGARCH:=all
endef

define Package/ns-log-viewer/description
	A consolidated log viewer (firewall traffic, Threat Shield/GeoIP, IPS/IDS,
	DPI, DNS protection, VPN, system logs) backed by VictoriaLogs. Off by
	default - enabled on demand via ns.log-viewer (see the "Open Log Viewer"
	button on the Logs page), since it adds real, ongoing CPU/disk cost.
endef

define Build/Compile
endef

define Package/ns-log-viewer/install
	$(INSTALL_DIR) $(1)/usr/share/ns-log-viewer
	$(INSTALL_DATA) ./files/nginx/logs-viewer.inc $(1)/usr/share/ns-log-viewer/logs-viewer.inc
	$(INSTALL_DATA) ./files/rsyslog/nexwall-extra.conf $(1)/usr/share/ns-log-viewer/nexwall-extra.conf

	$(INSTALL_DIR) $(1)/www-ns/logs-viewer
	$(INSTALL_DATA) ./files/www-ns/logs-viewer/index.html $(1)/www-ns/logs-viewer/index.html
endef

$(eval $(call BuildPackage,ns-log-viewer))
