#!/bin/sh
# Nexwall Support Packet: web-cert (class R0). Generated from the controller catalog.
nexwall-webui-cert status
echo "== log"; grep nexwall-webui-cert /var/log/messages | tail -20
