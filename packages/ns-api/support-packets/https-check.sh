#!/bin/sh
# Nexwall Support Packet: https-check (class R0). Generated from the controller catalog.
curl -sI --max-time 6 "https://$1" | head -3
echo | openssl s_client -connect "$1":443 -servername "$1" 2>/dev/null | grep -E "subject=|issuer=|Verify return|Protocol"
