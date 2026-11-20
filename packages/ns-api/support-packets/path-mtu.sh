#!/bin/sh
# Nexwall Support Packet: path-mtu (class R0). Generated from the controller catalog.
ping -c1 -W2 -M do -s "$2" "$1"; echo; ip route get "$1"
