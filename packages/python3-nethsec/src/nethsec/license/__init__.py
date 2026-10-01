#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Licensing state and entitlements of this unit.

The license server signs the entitlements; the unit stores the signed envelope
({payload, signature, algorithm, key_id}) in /etc/nexwall-license/license.json and this module verifies
the RSA signature against /etc/nexwall-license/pubkey.pem on every read, so editing the file by hand
(or dropping in a forged one) gives nothing. Each signed payload carries a short lease (``valid_until``)
renewed at every check-in: a unit that cannot renew drops to unlicensed when the lease runs out, even
if the subscription it last saw is still running. The state is always evaluated against the current time.

States: ``subscribed`` (active partner subscription) > ``trial`` > ``unlicensed``.
A unit that has never reached the license server gets a short bootstrap window of ``BOOTSTRAP_HOURS`` from
the first time it was seen, enough to register; after that it is limited until it checks in. A license file
that fails verification is never treated as "not registered": it is unlicensed.
"""

import base64
import json
import os
from datetime import datetime, timedelta, timezone

from nethsec import utils

LICENSE_FILE = '/etc/nexwall-license/license.json'
FIRST_SEEN_FILE = '/etc/nexwall-license/first_seen'
PUBKEY_FILE = '/etc/nexwall-license/pubkey.pem'
BOOTSTRAP_HOURS = 24

FULL = {
    'security_services': True,
    'reverse_proxy': True,
    'ha': True,
    'limits': {'ipsec_s2s': None, 'wireguard': None, 'sslvpn_users': None},
}
LIMITED = {
    'security_services': False,
    'reverse_proxy': False,
    'ha': False,
    'limits': {'ipsec_s2s': 1, 'wireguard': 1, 'sslvpn_users': 3},
}

# user-facing names for the error the UI shows
FEATURES = ('security_services', 'reverse_proxy', 'ha')
LIMITS = ('ipsec_s2s', 'wireguard', 'sslvpn_users')


def _copy(entitlements):
    return json.loads(json.dumps(entitlements))


def _ts(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def verify_envelope(envelope, pubkey_path=None):
    """Decoded payload of a signed envelope, or None when the signature does not verify."""
    try:
        from Crypto.Hash import SHA256
        from Crypto.PublicKey import RSA
        from Crypto.Signature import pkcs1_15
        with open(pubkey_path or PUBKEY_FILE, 'rb') as f:
            key = RSA.import_key(f.read())
        payload = base64.b64decode(envelope['payload'], validate=True)
        pkcs1_15.new(key).verify(SHA256.new(payload), base64.b64decode(envelope['signature'], validate=True))
        data = json.loads(payload)
        return data if isinstance(data, dict) else None
    except Exception:  # any failure means "not trusted"
        return None


def load(path=None, pubkey_path=None):
    """Verified license payload, or None when there is no file or it is not validly signed."""
    return _read(path, pubkey_path)[0]


def _read(path=None, pubkey_path=None):
    """(payload, present): payload is None unless the stored envelope verifies; present tells whether
    a file exists at all (an unverifiable file is a tamper, not a fresh install)."""
    try:
        with open(path or LICENSE_FILE) as f:
            envelope = json.load(f)
    except FileNotFoundError:
        return None, False
    except (OSError, ValueError):
        return None, True
    if not isinstance(envelope, dict):
        return None, True
    return verify_envelope(envelope, pubkey_path), True


def _first_seen(now, path=None):
    path = path or FIRST_SEEN_FILE
    try:
        with open(path) as f:
            seen = _ts(f.read().strip())
            if seen:
                return seen
    except OSError:
        pass
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(now.isoformat() + '\n')
    except OSError:
        pass
    return now


def state(now=None, license_path=None, first_seen_path=None, pubkey_path=None):
    """Effective state right now: 'subscribed', 'trial' or 'unlicensed'."""
    now = now or datetime.now(timezone.utc)
    lic, present = _read(license_path, pubkey_path)
    if lic is None and present:
        return 'unlicensed'  # file exists but is not signed by the license server
    if lic is None or not lic.get('hwid'):
        # never reached the license server: short bootstrap window from first sight
        end = _first_seen(now, first_seen_path) + timedelta(hours=BOOTSTRAP_HOURS)
        return 'trial' if now < end else 'unlicensed'

    lease = _ts(lic.get('valid_until'))
    if lease is None or now >= lease:
        return 'unlicensed'  # lease missing or not renewed: the unit has not been able to check in

    declared = lic.get('license_state')
    if declared is None:  # license issued before the trial model existed
        declared = 'subscribed' if lic.get('status') == 'active' else 'unlicensed'
    if declared == 'subscribed':
        end = _ts(lic.get('subscription_end'))
        return 'subscribed' if lic.get('status') == 'active' and end and now < end else 'unlicensed'
    if declared == 'trial':
        end = _ts(lic.get('trial_end'))
        return 'trial' if end and now < end else 'unlicensed'
    return 'unlicensed'


def entitlements(now=None, license_path=None, first_seen_path=None, pubkey_path=None):
    """What this unit may use right now."""
    current = state(now, license_path, first_seen_path, pubkey_path)
    if current == 'unlicensed':
        return _copy(LIMITED)
    lic = load(license_path, pubkey_path) or {}
    ent = lic.get('entitlements')
    if not isinstance(ent, dict):
        return _copy(FULL)
    merged = _copy(FULL)
    for key in FEATURES:
        if key in ent:
            merged[key] = bool(ent[key])
    if isinstance(ent.get('limits'), dict):
        for key in LIMITS:
            if key in ent['limits']:
                merged['limits'][key] = ent['limits'][key]
    return merged


def feature_error(feature, **kwargs):
    """None when the feature is included, otherwise an API validation error."""
    if entitlements(**kwargs).get(feature):
        return None
    return utils.validation_error('license', 'license_required', feature)


def require(feature, **kwargs):
    """Raise the standard API ValidationError when the feature is not included."""
    if not entitlements(**kwargs).get(feature):
        raise utils.ValidationError('license', 'license_required', feature)


def limit_error(name, current, **kwargs):
    """None when one more of `name` fits, given `current` already configured; else an API validation error."""
    allowed = entitlements(**kwargs)['limits'].get(name)
    if allowed is None or current < allowed:
        return None
    return utils.validation_error('license', 'license_limit_reached', name)


def limit(name, **kwargs):
    """Maximum allowed for `name`, or None for unlimited."""
    return entitlements(**kwargs)['limits'].get(name)
