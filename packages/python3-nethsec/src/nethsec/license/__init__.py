#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Licensing state and entitlements of this unit.

The license server signs the entitlements into /etc/nexwall-license/license.json; this module only
reads that file. The state is always evaluated against the current time, so a unit that stays offline
past its trial or subscription end stops being entitled without the server having to say so.

States: ``subscribed`` (active partner subscription) > ``trial`` > ``unlicensed``.
A unit that has never reached the license server gets a local trial of ``OFFLINE_TRIAL_DAYS`` days from
the first time it was seen, so an air-gapped install is not bricked on day one.
"""

import json
import os
from datetime import datetime, timedelta, timezone

from nethsec import utils

LICENSE_FILE = '/etc/nexwall-license/license.json'
FIRST_SEEN_FILE = '/etc/nexwall-license/first_seen'
OFFLINE_TRIAL_DAYS = 30

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


def load(path=None):
    try:
        with open(path or LICENSE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


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


def state(now=None, license_path=None, first_seen_path=None):
    """Effective state right now: 'subscribed', 'trial' or 'unlicensed'."""
    now = now or datetime.now(timezone.utc)
    lic = load(license_path)
    if not lic or not lic.get('hwid'):
        # never reached the license server: local trial from first sight
        end = _first_seen(now, first_seen_path) + timedelta(days=OFFLINE_TRIAL_DAYS)
        return 'trial' if now < end else 'unlicensed'

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


def entitlements(now=None, license_path=None, first_seen_path=None):
    """What this unit may use right now."""
    current = state(now, license_path, first_seen_path)
    if current == 'unlicensed':
        return _copy(LIMITED)
    lic = load(license_path) or {}
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
