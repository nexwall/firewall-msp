#!/bin/sh
# Nexwall Support Packet: fastpath-state (class R0). Generated from the controller catalog.
nexwall-fastpath status
echo "== rules"; nft list table inet nexwall_fastpath 2>&1 | head -30
echo "== offloaded in conntrack"; grep -c OFFLOAD /proc/net/nf_conntrack
echo "== log"; grep nexwall-fastpath /var/log/messages | tail
echo "== service"; /etc/init.d/nexwall-fastpath status
