#!/bin/sh
# Nexwall Support Packet: license-state (class R0). Generated from the controller catalog.
echo "== serial"; cat /etc/nexwall-license/serial
echo "== state"; licensectl state
echo "== subscription"; ubus call ns.subscription info
echo "== entitlements"; licensectl entitlements
