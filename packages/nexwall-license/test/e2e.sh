#!/bin/sh
# End-to-end check of automatic registration: real license server code + the real client script,
# all on localhost inside one container. Run from the directory holding both repos:
#   podman run --rm -v $PWD/nexwall-license-server:/srv/ls:Z -v $PWD/firewall-msp:/srv/fw:Z \
#     python:3.11-slim sh /srv/fw/packages/nexwall-license/test/e2e.sh
set -e
export NEXWALL_LICENSE_NO_JITTER=1
pip install -q -r /srv/ls/requirements.lock.txt requests pycryptodomex >/dev/null 2>&1
# the client imports Crypto.*; pycryptodomex provides Cryptodome, so install pycryptodome instead
pip install -q pycryptodome >/dev/null 2>&1

export NEXWALL_DATA_DIR=/tmp/ls-data NEXWALL_KEYS_DIR=/tmp/ls-keys NEXWALL_ADMIN_PASSWORD=x
cd /srv/ls
python - <<'PY'
import sys; sys.path.insert(0,'/srv/ls')
from app import app as m
m.init_db(); m.ensure_keypair()
PY
mkdir -p /etc/nexwall-license /etc/config
cp /tmp/ls-keys/public.pem /etc/nexwall-license/pubkey.pem
(cd /srv/ls && python -c "
from app.app import app
app.run('127.0.0.1', 5055)" >/tmp/server.log 2>&1 &)
sleep 4

# stub uci: only the license server address is configured
cat > /usr/local/bin/uci <<'UCI'
#!/bin/sh
case "$*" in
  *nexwall-license.main.server*) echo http://127.0.0.1:5055 ;;
esac
exit 0
UCI
chmod +x /usr/local/bin/uci
[ -e /usr/bin/python3 ] || ln -s "$(command -v python3)" /usr/bin/python3
cp /srv/fw/packages/nexwall-license/files/nexwall-serial /usr/sbin/nexwall-serial
cp /srv/fw/packages/nexwall-license/files/nexwall-license-register /usr/sbin/nexwall-license-register
chmod +x /usr/sbin/nexwall-serial /usr/sbin/nexwall-license-register


# the stored license is a signed envelope; show its decoded payload
lic_json() { python3 -c 'import base64,json;print(json.dumps(json.loads(base64.b64decode(json.load(open("/etc/nexwall-license/license.json"))["payload"])),indent=2))'; }
echo "--- serial:"; SERIAL=$(nexwall-serial); echo "$SERIAL"
echo "$SERIAL" | grep -Eq '^NXW-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$'
[ "$(nexwall-serial)" = "$SERIAL" ] # stable

echo "--- first check-in (unassigned):"
nexwall-license-register
lic_json | grep -q "\"status\": \"unassigned\""
lic_json | grep -q "\"license_state\": \"trial\""
lic_json | grep -q '"valid_until"'
[ "$(stat -c %a /etc/nexwall-license/license.json)" = "600" ]
[ -s /etc/nexwall-license/device_token ]
[ "$(stat -c %a /etc/nexwall-license/device_token)" = "600" ]

echo "--- second check-in keeps the token:"
T1=$(cat /etc/nexwall-license/device_token); nexwall-license-register; [ "$T1" = "$(cat /etc/nexwall-license/device_token)" ]

echo "--- admin assigns the unit to a partner:"
python - <<'PY'
import sys; sys.path.insert(0,'/srv/ls')
from app import app as m
c = m.get_db()
c.execute("INSERT INTO partners (id,name,subscription_end,firewall_limit,status,unlock_key) VALUES ('ACME','Acme','2099-01-01T00:00:00+00:00',5,'active','k')")
c.execute("INSERT INTO subscriptions (partner_id,module_name,module_code) VALUES ('ACME','IPS','ips')")
c.execute("UPDATE firewalls SET partner_id='ACME', status='active'")
c.commit()
PY
nexwall-license-register
lic_json | grep -q '"status": "active"'
lic_json | grep -q '"partner_id": "ACME"'
lic_json | grep -q "$SERIAL"

echo "--- scheduled run skips while the active license is fresh:"
M1=$(stat -c %Y /etc/nexwall-license/license.json); sleep 1; nexwall-license-register --scheduled; [ "$M1" = "$(stat -c %Y /etc/nexwall-license/license.json)" ]

echo "--- lost token on an assigned unit is refused:"
rm /etc/nexwall-license/device_token
if nexwall-license-register 2>/tmp/err; then echo "UNEXPECTED SUCCESS"; exit 1; fi; grep -q DEVICE_ALREADY_REGISTERED /tmp/err
echo "ALL OK"
