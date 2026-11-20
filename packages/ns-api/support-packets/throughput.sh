#!/bin/sh
# Nexwall Support Packet: throughput (class R0). Generated from the controller catalog.
echo "== dpi"; dpidbg status
echo "== kernel queues"; cat /proc/net/netfilter/nfnetlink_queue
echo "== top"; top -b -n1 | head -15
echo "== fast path"; nexwall-fastpath status
echo "== ips rules"; nexwall-ips-rules status
echo "== ips alerts"; ls /var/log/snort
