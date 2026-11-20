#!/bin/sh
# Nexwall Support Packet: dns-config (class R0). Generated from the controller catalog.
echo "== resolv.conf"; cat /etc/resolv.conf; cat /tmp/resolv.conf.d/resolv.conf.auto 2>/dev/null
echo "== dnsmasq"; /etc/init.d/dnsmasq status; netstat -tulnp | grep ':53 '
echo "== config test"; dnsmasq --test 2>&1
echo "== log"; grep dnsmasq /var/log/messages | tail -20
