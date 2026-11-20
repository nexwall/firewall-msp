#!/bin/sh
# Nexwall Support Packet: dns-resolve (class R0). Generated from the controller catalog.
if [ -n "$2" ]; then dig +time=3 +tries=1 "$1" "@$2"; else dig +time=3 +tries=1 "$1"; fi
