#!/bin/sh
# Nexwall Support Packet: packet-2 (class R1). Generated from the controller catalog.
add() { f="${f:+$f and }$*"; }
set -f
src="$1"; dst="$2"; port="$3"; proto="$4"; secs="$5"; f=""
[ -n "$src" ] && add src host "$src"
[ -n "$dst" ] && add dst host "$dst"
[ -n "$port" ] && add dst port "$port"
[ -n "$proto" ] && add proto "$proto"
[ -z "$f" ] && { echo "Enter at least a source or a destination."; exit 2; }
echo "Filter: $f (for $secs s). Reproduce the problem now."
fwtrace -i "$secs" $f
