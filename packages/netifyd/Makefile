include $(TOPDIR)/rules.mk

PKG_NAME:=netifyd
PKG_VERSION:=5.2.9
PKG_RELEASE:=2
PKG_MAINTAINER:=Nexwall <dev@nexwall.com.br>
PKG_LICENSE:=GPL-2.0-only Apache-2.0

include $(INCLUDE_DIR)/package.mk

define Package/netifyd
	SECTION:=admin
	CATEGORY:=Administration
	TITLE:=Traffic classification service (Nexwall placeholder)
	URL:=https://nexwall.com.br/
	DEPENDS:= \
		@(aarch64||x86_64) \
		+ca-bundle \
		+kmod-ipt-conntrack-label \
		+kmod-ipt-ipset \
		+libatomic \
		+libblobmsg-json \
		+libc \
		+libcap \
		+libcurl \
		+libgcrypt \
		+libgpg-error \
		+libipset \
		+libjson-c \
		+libmnl \
		+libnetfilter-conntrack \
		+libnetfilter-queue \
		+libopenssl \
		+libpcap \
		+libpthread \
		+libstdcpp \
		+libubox \
		+libubus \
		+libuci \
		+nftables \
		+zlib \
		+zoneinfo-core
	USERID:=netify:netify
endef

define Package/netifyd/description
Service and command line placeholder for the traffic classification engine.
It keeps the interface used by the rest of the system (agent UUID, informatics
flag, service lifecycle) and ships the open application signature list, but it
does not inspect traffic: application detection and DPI blocking are not available
until an engine is added.
endef

define Package/netifyd/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	# removed the table-pre script for fw4, reload it to remove the entries
	/etc/init.d/firewall reload >/dev/null 2>&1
	/etc/init.d/netifyd restart
fi
exit 0
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/netifyd/conffiles
/etc/config/netifyd
/etc/netifyd.conf
/etc/netifyd/agent.uuid
/etc/netifyd/netify-proc-core-auto.json
/etc/netifyd/netify-sink-http-auto.json
/etc/netifyd/plugins.d/99-netify-proc-core-auto.conf
/etc/netifyd/plugins.d/99-netify-sink-http-auto.conf
endef

define Package/netifyd/install
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/netifyd
	$(INSTALL_DIR) $(1)/etc/netifyd/address-groups.d
	$(INSTALL_DIR) $(1)/etc/netifyd/categories.d
	$(INSTALL_DIR) $(1)/etc/netifyd/interfaces.d
	$(INSTALL_DIR) $(1)/etc/netifyd/plugins.d
	$(INSTALL_DIR) $(1)/etc/netifyd/profiles.d
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/share/netifyd
	$(INSTALL_DIR) $(1)/usr/share/netifyd/plugins.d
	# service placeholder
	$(INSTALL_BIN) ./files/usr/sbin/netifyd $(1)/usr/sbin/netifyd
	$(INSTALL_DATA) ./files/etc/config/netifyd $(1)/etc/config/netifyd
	$(INSTALL_BIN) ./files/etc/init.d/netifyd $(1)/etc/init.d/netifyd
	$(INSTALL_DATA) ./files/etc/netifyd.conf $(1)/etc/netifyd.conf
	$(INSTALL_DATA) ./files/etc/netifyd/interfaces.d/10-nfqueue.conf $(1)/etc/netifyd/interfaces.d/10-nfqueue.conf
	$(INSTALL_DATA) ./files/etc/netifyd/netify-apps.conf $(1)/etc/netifyd/netify-apps.conf
	$(INSTALL_DATA) ./files/etc/netifyd/netify-categories.json $(1)/etc/netifyd/netify-categories.json
	$(INSTALL_DATA) ./files/etc/netifyd/profiles.d/00-default.conf $(1)/etc/netifyd/profiles.d/00-default.conf
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-netify-v4-migrate.uci-default $(1)/etc/uci-defaults/99-netify-v4-migrate
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-netify-enable-nfqueue.uci-default $(1)/etc/uci-defaults/99-netify-enable-nfqueue
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-netify-disable-autoconfig.uci-default $(1)/etc/uci-defaults/99-netify-disable-autoconfig
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-netify-disable-coredumps.uci-default $(1)/etc/uci-defaults/99-netify-disable-coredumps
	$(INSTALL_DATA) ./files/usr/share/netifyd/functions.sh $(1)/usr/share/netifyd/functions.sh
	$(INSTALL_DATA) ./files/usr/share/netifyd/netify-apps.conf $(1)/usr/share/netifyd/netify-apps.conf
	$(INSTALL_DATA) ./files/usr/share/netifyd/netify-categories.json $(1)/usr/share/netifyd/netify-categories.json
	$(INSTALL_DATA) ./files/usr/share/netifyd/netify-proc-core-auto.json $(1)/usr/share/netifyd/netify-proc-core-auto.json
	$(INSTALL_DATA) ./files/usr/share/netifyd/netify-sink-http-auto.json $(1)/usr/share/netifyd/netify-sink-http-auto.json
	$(INSTALL_DATA) ./files/usr/share/netifyd/plugins.d/99-netify-proc-core-auto.conf $(1)/usr/share/netifyd/plugins.d/99-netify-proc-core-auto.conf
	$(INSTALL_DATA) ./files/usr/share/netifyd/plugins.d/99-netify-sink-http-auto.conf $(1)/usr/share/netifyd/plugins.d/99-netify-sink-http-auto.conf
	# glue kept from the previous integration
	$(INSTALL_BIN) ./files/usr/sbin/ns-netifyd-configure.py $(1)/usr/sbin/ns-netifyd-configure
	# plugin configuration read and written by ns-dpi
	$(INSTALL_DATA) ./files/etc/netifyd/netify-proc-aggregator.json $(1)/etc/netifyd/netify-proc-aggregator.json
	$(INSTALL_DATA) ./files/etc/netifyd/plugins.d/10-netify-proc-aggregator.conf $(1)/etc/netifyd/plugins.d/10-netify-proc-aggregator.conf
	$(INSTALL_DATA) ./files/etc/netifyd/netify-proc-core.json $(1)/etc/netifyd/netify-proc-core.json
	$(INSTALL_DATA) ./files/etc/netifyd/plugins.d/10-netify-proc-core.conf $(1)/etc/netifyd/plugins.d/10-netify-proc-core.conf
	$(INSTALL_DATA) ./files/etc/netifyd/netify-proc-flow-actions.json $(1)/etc/netifyd/netify-proc-flow-actions.json
	$(INSTALL_DATA) ./files/etc/netifyd/plugins.d/10-netify-proc-flow-actions.conf $(1)/etc/netifyd/plugins.d/10-netify-proc-flow-actions.conf
	$(INSTALL_DATA) ./files/etc/netifyd/netify-sink-log.json $(1)/etc/netifyd/netify-sink-log.json
	$(INSTALL_DATA) ./files/etc/netifyd/plugins.d/10-netify-sink-log.conf $(1)/etc/netifyd/plugins.d/10-netify-sink-log.conf
	$(INSTALL_DATA) ./files/etc/netifyd/netify-sink-http.json $(1)/etc/netifyd/netify-sink-http.json
	$(INSTALL_DATA) ./files/etc/netifyd/plugins.d/10-netify-sink-http.conf $(1)/etc/netifyd/plugins.d/10-netify-sink-http.conf
endef

$(eval $(call BuildPackage,netifyd))
