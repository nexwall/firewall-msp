#!/bin/sh
# Nexwall Support Packet: conntrack (class R0). Generated from the controller catalog.
conntrack -C
[ -n "$1" ] && conntrack -L -d "$1" 2>/dev/null | head -20
