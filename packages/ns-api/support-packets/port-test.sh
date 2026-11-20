#!/bin/sh
# Nexwall Support Packet: port-test (class R0). Generated from the controller catalog.
nc -zv -w3 "$1" "$2" 2>&1
