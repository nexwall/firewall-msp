#!/bin/sh
# Nexwall Support Packet: dns-trace (class R0). Generated from the controller catalog.
dig +trace +time=3 +tries=1 "$1"
