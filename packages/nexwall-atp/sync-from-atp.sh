#!/bin/sh
# Copies the modules the unit needs from the ATP repository (one source of truth) and records the commit.
# usage: sync-from-atp.sh /path/to/nexwall-atp
set -e
SRC="${1:?path to the nexwall-atp checkout}"
DST="$(dirname "$0")/files/lib/atp"
rm -rf "$DST"
mkdir -p "$DST/netintel" "$DST/capture" "$DST/edge"
: > "$DST/__init__.py"
for f in netintel/__init__ netintel/beacon netintel/dga netintel/flowfeatures capture/__init__ capture/flowlog edge/__init__ edge/model edge/scorer edge/dnssniff; do
	cp "$SRC/atp/$f.py" "$DST/$f.py"
done
git -C "$SRC" rev-parse HEAD > "$DST/SOURCE_COMMIT"
echo "synced from $(cat "$DST/SOURCE_COMMIT")"
