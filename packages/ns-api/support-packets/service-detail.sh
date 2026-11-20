#!/bin/sh
# Nexwall Support Packet: service-detail (class R0). Generated from the controller catalog.
echo "== status"; /etc/init.d/"$1" status 2>&1
echo "== info"; /etc/init.d/"$1" info 2>&1
echo "== at boot"; /etc/init.d/"$1" enabled && echo yes || echo no
echo "== procd"; ubus call service list "{\"name\":\"$1\"}" 2>&1
echo "== log"; grep -iF -e "$1" /var/log/messages | tail -20
