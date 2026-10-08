#!/bin/sh
# Tests of uci-defaults/99-nethsec-default-wan on a firewall (needs uci). Usage: sh tests/default-wan.sh (SCRIPT=path to override)
SCRIPT="${SCRIPT:-$(dirname "$0")/../files/etc/uci-defaults/99-nethsec-default-wan}"
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got [$2] want [$3]"; fail=1; fi; }
mk() {  # mk <dir> <wizard-complete 0|1> <extra network config>
	rm -rf "$1" /tmp/sysnet.$$; mkdir -p "$1" /tmp/sysnet.$$/eth0 /tmp/sysnet.$$/eth1
	cat > "$1/network" <<EOC
config interface 'loopback'
	option device 'lo'
	option proto 'static'

config interface 'lan'
	option device 'eth0'
	option proto 'static'
	option ipaddr '192.168.1.1'
$3
EOC
	printf "config zone 'ns_wan'\n\toption name 'wan'\n\tlist network 'wan'\n" > "$1/firewall"
	printf "config wizard 'config'\n\toption complete '%s'\n" "$2" > "$1/ns-wizard"
}
run() { UCI_CONF="$1" SYS_NET="${2:-/tmp/sysnet.$$}" sh "$SCRIPT"; }
get() { uci -q -c "$1" get "$2"; }

mk /tmp/dw1 0 ""; run /tmp/dw1
check "fresh unit: wan device" "$(get /tmp/dw1 network.wan.device)" "eth1"
check "fresh unit: wan proto" "$(get /tmp/dw1 network.wan.proto)" "dhcp"
check "fresh unit: zone lists wan" "$(get /tmp/dw1 firewall.ns_wan.network)" "wan"
run /tmp/dw1; check "second run changes nothing" "$(uci -q -c /tmp/dw1 show network | grep -c "\.wan=interface")" "1"

mk /tmp/dw2 1 ""; run /tmp/dw2; check "configured unit (wizard complete) is left alone" "$(get /tmp/dw2 network.wan)" ""
mk /tmp/dw3 0 "
config interface 'WAN'
	option device 'eth1'
	option proto 'dhcp'"; run /tmp/dw3; check "eth1 already used" "$(get /tmp/dw3 network.wan)" ""
mk /tmp/dw4 0 ""; rm -rf /tmp/sysnet.$$/eth1; run /tmp/dw4; check "no second card: nothing" "$(get /tmp/dw4 network.wan)" ""
mk /tmp/dw5 0 "
config interface 'wan'
	option device 'eth5'
	option proto 'static'"; run /tmp/dw5; check "an interface called wan exists" "$(get /tmp/dw5 network.wan.device)" "eth5"
mk /tmp/dw6 0 "
config device
	option name 'br0'
	list ports 'eth1'"; run /tmp/dw6; check "eth1 is a bridge port" "$(get /tmp/dw6 network.wan)" ""
mk /tmp/dw7 0 ""; printf "config zone 'ns_wan'\n\toption name 'wan'\n" > /tmp/dw7/firewall; run /tmp/dw7
check "zone without the interface gets it" "$(get /tmp/dw7 firewall.ns_wan.network)" "wan"
rm -rf /tmp/dw? /tmp/sysnet.$$
exit $fail
