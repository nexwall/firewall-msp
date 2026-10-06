#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Licensing state and entitlements of this unit.

This module holds no licensing logic. The decisions are made by the Nexwall license core
(``nexwall-licensed``, a vendor binary delivered from the Nexwall vendor feed): it talks to the license
server, verifies what the server signed, keeps the lease and evaluates the state against the clock. This
module only asks it, over a local socket, and applies the answer.

Without the core (a build that did not include the vendor package, or the core is not running) the unit is
**unlicensed**: the limited feature set, no paid features. The answer never comes from a file that could be
edited here.

States: ``subscribed`` (active partner subscription) > ``trial`` > ``unlicensed``.
"""

import json
import os
import socket
import time

from nethsec import utils

DAEMON_SOCKET = '/var/run/nexwall-license.sock'
CORE_BINARY = '/usr/sbin/nexwall-licensed'

# What a unit can be subscribed to: the five base modules come with the license activation, the add-ons are sold apart.
MODULES = (
    ('dpi', 'Application Control (DPI)', 'base'),
    ('ips', 'Network Protection (IPS)', 'base'),
    ('dns', 'DNS Filtering', 'base'),
    ('geo', 'IP & Geo Blocking', 'base'),
    ('vpn_ext', 'VPN Extended', 'base'),
    ('web', 'Web Protection', 'base'),
    ('av', 'Antivirus / Sandbox', 'base'),
    ('atp', 'Advanced Threat Protection', 'base'),
    ('ztna', 'Workspace Protection (ZTNA)', 'addon'),
    ('waf', 'Web Server Protection (WAF)', 'addon'),
    ('mta', 'Email Protection (MTA)', 'addon'),
)

FULL = {
    'security_services': True,
    'reverse_proxy': True,
    'ha': True,
    'limits': {'ipsec_s2s': None, 'wireguard': None, 'sslvpn_users': None},
    'modules': {code: kind == 'base' for code, _name, kind in MODULES},
}
LIMITED = {
    'security_services': False,
    'reverse_proxy': False,
    'ha': False,
    'limits': {'ipsec_s2s': 1, 'wireguard': 1, 'sslvpn_users': 3},
    'modules': {code: False for code, _name, _kind in MODULES},
}

# user-facing names for the error the UI shows
FEATURES = ('security_services', 'reverse_proxy', 'ha')
LIMITS = ('ipsec_s2s', 'wireguard', 'sslvpn_users')


def _copy(entitlements):
    return json.loads(json.dumps(entitlements))


def _ask_once(request):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(DAEMON_SOCKET)
            s.sendall(json.dumps(request).encode() + b'\n')
            data = b''
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        answer = json.loads(data)
        return answer if isinstance(answer, dict) and answer.get('ok') else None
    except (OSError, ValueError):
        return None


def _ask(request):
    """Ask the license core; None when it is not there. When the core is installed the answer is awaited for a few
    seconds, so a restart of the core (an update) is not read as "unlicensed"."""
    answer = _ask_once(request)
    if answer is not None or not os.path.exists(CORE_BINARY):
        return answer
    for _ in range(5):
        time.sleep(1)
        answer = _ask_once(request)
        if answer is not None:
            return answer
    return None


def load(*_args, **_kwargs):
    """Verified license payload (plan, company, dates) as the core sees it, or None."""
    answer = _ask({'cmd': 'payload'})
    return answer.get('payload') if answer else None


def state(*_args, **_kwargs):
    """Effective state right now: 'subscribed', 'trial' or 'unlicensed'."""
    answer = _ask({'cmd': 'state'})
    return answer['state'] if answer and answer.get('state') else 'unlicensed'


def entitlements(*_args, **_kwargs):
    """What this unit may use right now."""
    answer = _ask({'cmd': 'entitlements'})
    ent = answer.get('entitlements') if answer else None
    return ent if isinstance(ent, dict) else _copy(LIMITED)


def modules(*_args, **_kwargs):
    """{code: bool} for every module. A core that does not report modules (older) grants the five base ones with security_services."""
    ent = entitlements()
    mods = ent.get('modules')
    if isinstance(mods, dict):
        return {code: bool(mods.get(code)) for code, _name, _kind in MODULES}
    base = bool(ent.get('security_services'))
    return {code: (kind == 'base' and base) for code, _name, kind in MODULES}


def module_error(code, **kwargs):
    """None when the module is included, otherwise an API validation error."""
    if modules(**kwargs).get(code):
        return None
    return utils.validation_error('license', 'license_required', code)


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
