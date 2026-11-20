#!/bin/sh
# Nexwall Support Packet: support-package (class R1). Generated from the controller catalog.
D=/tmp/nexwall-support-package; rm -rf "$D" "$D.tgz"; mkdir -p "$D"
{ date; uptime; cat /etc/os-release; } > "$D/system.txt"
df -h > "$D/disk.txt"; free -m > "$D/memory.txt"
ip -br a > "$D/links.txt"; ip route > "$D/routes.txt"
ubus call service list > "$D/services.json"
ubus call ns.plug status > "$D/controller.txt"
tail -n 1000 /var/log/messages > "$D/messages.txt"
uci show 2>/dev/null | grep -viE 'password|secret|key|psk|token|passwd' > "$D/config.txt"
tar czf "$D.tgz" -C /tmp nexwall-support-package; rm -rf "$D"; ls -l "$D.tgz"
