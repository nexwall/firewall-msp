#!/bin/sh
# Nexwall Support Packet: services-state (class R0). Generated from the controller catalog.
for s in firewall dnsmasq nginx dropbear ns-plug snort mwan3 ns-ui dpi openvpn; do
  printf "%-12s %s\n" "$s" "$(/etc/init.d/$s status 2>&1 | head -1)"
done
echo "== CONTROLLER"; ubus call ns.plug status
echo "== MEMORY"; free
