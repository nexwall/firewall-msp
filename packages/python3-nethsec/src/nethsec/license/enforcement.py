#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Is the DPI enforcement actually being applied right now, and if not, why?

The DPI enforcement plugin acts only while the Nexwall license core hands it a valid token (see
nexwall-internal/msp/DPI_PLUGIN_LICENSE_TOKEN.md). The plugin writes its verdict to a small stats file; this module
combines it with the license state so the UI can say what is going on:

  active   enforcement is being applied
  license  suspended: the license does not cover application control (expired, not registered, plan without it)
  service  suspended: the license service is not running, or the unit is licensed but the plugin gets no token
  engine   suspended: the plugin does not report (traffic engine not running or restarting)
  plugin   suspended: the enforcement plugin is not installed (community build)
"""

import json
import os
import subprocess
import time

from nethsec import license as nx_license

STATS_FILE = '/var/run/netifyd/dpi-actions-stats.json'
PLUGIN_FILE = '/usr/lib/libnx-proc-flow-actions.so'
STALE_SECONDS = 60


def _read_stats(path):
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def core_state():
    """'absent' (no license core in this build), 'up' or 'down' (installed but not answering)."""
    if not os.path.exists(nx_license.CORE_BINARY):
        return 'absent'
    return 'up' if nx_license._ask_once({'cmd': 'version'}) is not None else 'down'


def dpi_enforcement(stats_path=None, plugin_path=None, now=None, state=None, security_services=None, core=None):
    """-> {'active': bool, 'cause': None|'license'|'service'|'engine'|'plugin', 'reason': str, 'license_state': str}"""
    now = time.time() if now is None else now
    core = core_state() if core is None else core
    stats = _read_stats(stats_path or STATS_FILE)
    reason = str(stats.get('license', '')) if stats else ''

    def out(active, cause, license_state='unknown'):
        return {'active': active, 'cause': cause, 'reason': reason, 'license_state': license_state}

    if core == 'down':
        # installed but not answering: that is the cause, whatever the license says (without the core every
        # license question reads "unlicensed", which would point the administrator in the wrong direction)
        return out(False, 'service')
    if state is None:
        state = nx_license.state()
    if security_services is None:
        security_services = bool(nx_license.entitlements().get('security_services'))
    if not security_services or state == 'unlicensed':
        return out(False, 'license', state)
    if not os.path.exists(plugin_path or PLUGIN_FILE):
        return out(False, 'plugin', state)
    updated = stats.get('updated') if stats else None
    if not isinstance(updated, (int, float)) or now - updated > STALE_SECONDS:
        return out(False, 'engine', state)
    if reason != 'valid':
        return out(False, 'service', state)
    return out(True, None, state)


GATE_PLUGIN = '/usr/lib/snort_nexwall/nx_ips_gate.so'
TOKEN_FILE = '/var/run/nexwall-license/token'


def _snort_running():
    return subprocess.run(['pidof', 'snort'], capture_output=True).returncode == 0


def _snort_enabled():
    p = subprocess.run(['uci', '-q', 'get', 'snort.snort.enabled'], capture_output=True, text=True)
    return p.stdout.strip() == '1'


def ips_enforcement(enabled=None, core=None, state=None, security_services=None, gate_path=None, token_path=None, running=None):
    """Is the IPS inspecting traffic right now, and if not, why?
    -> {'applicable': bool, 'active': bool, 'cause': None|'license'|'service'|'engine'|'plugin', 'license_state': str}
    Not applicable while the IPS is switched off. The gate plugin inside snort decides with the token the license core writes;
    the token file existing while the core answers is what this reports as active."""
    enabled = _snort_enabled() if enabled is None else enabled
    core = core_state() if core is None else core

    def out(active, cause, license_state='unknown'):
        return {'applicable': True, 'active': active, 'cause': cause, 'license_state': license_state}

    if not enabled:
        return {'applicable': False, 'active': False, 'cause': None, 'license_state': 'unknown'}
    if core == 'down':
        return out(False, 'service')
    state = nx_license.state() if state is None else state
    if security_services is None:
        security_services = bool(nx_license.entitlements().get('security_services'))
    if not security_services or state == 'unlicensed':
        return out(False, 'license', state)
    if not os.path.exists(gate_path or GATE_PLUGIN):
        return out(False, 'plugin', state)
    if not os.path.exists(token_path or TOKEN_FILE):
        return out(False, 'service', state)
    if not (_snort_running() if running is None else running):
        return out(False, 'engine', state)
    return out(True, None, state)
