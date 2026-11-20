#!/bin/sh
# Nexwall Support Packet: dpi-stall (class R0). Generated from the controller catalog.
dpidbg status
echo "== reports"; ls -lt /root/nfq-stall/ 2>&1 | head
echo "== events"; tail -n 50 /root/nfq-stall/events.log 2>&1
