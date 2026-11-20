#!/bin/sh
# Nexwall Support Packet: logs-search (class R0). Generated from the controller catalog.
grep -iF -e "$1" /var/log/messages | tail -n "$2"
