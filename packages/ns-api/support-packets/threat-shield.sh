#!/bin/sh
# Nexwall Support Packet: threat-shield (class R0). Generated from the controller catalog.
nexwall-threat-feeds status
echo "== memory"; free -m
echo "== log"; grep -E "nexwall-threat-feeds|adblock|banIP" /var/log/messages | tail -50
echo "== adblock"; uci show adblock.global 2>&1
echo "== banip"; uci show banip.global 2>&1 | grep -v oinkcode
