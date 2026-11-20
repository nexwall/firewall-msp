#!/bin/sh
# Nexwall Support Packet: health-check (class R0). Generated from the controller catalog.
echo "== TIME"; date; uptime
echo "== DISK"; df -h / /mnt/data 2>/dev/null
echo "== MEMORY (MB)"; free -m | head -2
echo "== LINKS"; ip -br a
echo "== DEFAULT ROUTE"; ip route | grep default
echo "== INTERNET"; ping -c2 -W2 8.8.8.8 | tail -2
echo "== DNS"; dig +short +time=3 +tries=1 nexwall.com.br
echo "== CONTROLLER"; ubus call ns.plug status | grep '"status"'
echo "== CONNTRACK (now / max)"; conntrack -C; cat /proc/sys/net/netfilter/nf_conntrack_max
echo "== CRITICAL ERRORS"; grep -iE 'out of memory|oom|segfault|panic' /var/log/messages | tail -3
