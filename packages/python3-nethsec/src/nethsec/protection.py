#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Protection overview for the dashboard: what each protection has loaded (catalogs and signatures), how fresh it is, what it did
recently, and the recent events. Everything is read from the status commands the protections already have; nothing here
downloads or changes anything.

``gather`` runs the commands, ``build_overview`` turns the raw answers into the shape the dashboard shows (pure, unit tested).
"""

import json
import os
import subprocess
import time

CACHE_FILE = '/tmp/nexwall-protection-overview.json'
CACHE_SECONDS = 15
COMMAND_TIMEOUT = 8

# How often each catalog is expected to be checked, in hours. A catalog is "late" when it has not been checked for three times
# that, "error" when its last check failed.
EXPECTED_HOURS = {'dpi': 24, 'ips': 1, 'threat_feeds': 6, 'web': 24, 'av': 12}
CATALOG_NAMES = {
    'threat_feeds': 'Threat Shield lists',
    'ips': 'IPS signatures',
    'dpi': 'Application Control catalog',
    'web': 'Web categories',
    'av': 'Antivirus signatures',
}
CATALOG_ORDER = ['threat_feeds', 'ips', 'web', 'av', 'dpi']
EVENT_WINDOW = 24 * 3600
MAX_EVENTS = 8


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _total(counts):
    """A count that may be a number or a dict of numbers (rules per type) -> one total, or None."""
    if isinstance(counts, bool):
        return None
    if isinstance(counts, (int, float)):
        return int(counts)
    if isinstance(counts, dict):
        numbers = [v for v in counts.values() if isinstance(v, (int, float)) and not isinstance(v, bool)]
        return int(sum(numbers)) if numbers else None
    return None


def _entry(cid, **kw):
    out = {'id': cid, 'name': CATALOG_NAMES[cid], 'present': True, 'licensed': None, 'version': None, 'entries': None,
           'entries_unit': None, 'detail': None, 'source': None, 'checked_at': None, 'updated_at': None, 'next_check': None,
           'message': None, 'error': None}
    out.update(kw)
    return out


def normalize_dpi(raw):
    if not isinstance(raw, dict) or not raw:
        return None
    counts = raw.get('counts') if isinstance(raw.get('counts'), dict) else {}
    return _entry('dpi', licensed=raw.get('entitled'), version=raw.get('installed_version'), entries=_int(counts.get('domains')),
                  entries_unit='domains', detail={'applications': _int(counts.get('applications')), 'domains': _int(counts.get('domains'))},
                  source=raw.get('source'), checked_at=_int(raw.get('last_check')), updated_at=_int(raw.get('installed_at')),
                  next_check=_int(raw.get('next_check')), message=raw.get('last_result'), error=raw.get('last_error') or None)


def normalize_ips(raw):
    if not isinstance(raw, dict) or not raw:
        return None
    counts = raw.get('counts')
    return _entry('ips', licensed=raw.get('license_state') in ('subscribed', 'trial') if raw.get('license_state') else None,
                  version=raw.get('installed_version') or raw.get('version'), entries=_total(counts), entries_unit='rules',
                  detail=counts if isinstance(counts, dict) else None, source=raw.get('policy'),
                  checked_at=_int(raw.get('last_check')), updated_at=_int(raw.get('installed_at') or raw.get('last_check')),
                  message=raw.get('last_result'), error=raw.get('last_error') or None)


def normalize_threat_feeds(raw):
    if not isinstance(raw, dict) or not raw:
        return None
    counts = raw.get('counts')
    return _entry('threat_feeds', licensed=raw.get('license_state') in ('subscribed', 'trial') if raw.get('license_state') else None,
                  version=raw.get('version'), entries=_total(counts), entries_unit='entries',
                  detail=counts if isinstance(counts, dict) else None, checked_at=_int(raw.get('last_check')),
                  updated_at=_int(raw.get('installed_at') or raw.get('last_check')), message=raw.get('last_result'),
                  error=raw.get('last_error') or None)


def normalize_web(raw):
    if not isinstance(raw, dict) or not raw:
        return None
    installed = raw.get('installed') if isinstance(raw.get('installed'), list) else []
    skipped = raw.get('skipped') if isinstance(raw.get('skipped'), dict) else {}
    return _entry('web', licensed=raw.get('license_state') in ('subscribed', 'trial') if raw.get('license_state') else None,
                  version=raw.get('version'), entries=_int(raw.get('domains')), entries_unit='domains',
                  detail={'lists': len(installed), 'skipped': sorted(skipped), 'memory_mb': _int(raw.get('memory_mb'))},
                  source=raw.get('source'), checked_at=_int(raw.get('last_check')), updated_at=_int(raw.get('installed_at')),
                  next_check=None, message=raw.get('last_result'), error=raw.get('last_error') or None)


def normalize_av(raw):
    if not isinstance(raw, dict) or not raw:
        return None
    sigs = raw.get('signatures') if isinstance(raw.get('signatures'), dict) else {}
    newest = max([v for v in sigs.values() if isinstance(v, (int, float))] or [0]) or None
    return _entry('av', licensed=raw.get('licensed'), version=raw.get('yara_version'),
                  detail={'signatures': {k: _int(v) for k, v in sigs.items()}, 'yara_version': raw.get('yara_version')},
                  checked_at=_int(raw.get('last_check')), updated_at=_int(raw.get('clamav_updated') or newest),
                  message=raw.get('last_result'), error=raw.get('last_error') or None)


NORMALIZERS = {'dpi': normalize_dpi, 'ips': normalize_ips, 'threat_feeds': normalize_threat_feeds, 'web': normalize_web, 'av': normalize_av}


def freshness(entry, now):
    """ok | late | error | pending | unlicensed for one catalog entry."""
    if entry['licensed'] is False:
        return 'unlicensed'
    if entry['error']:
        return 'error'
    if not entry['checked_at'] and not entry['version']:
        return 'pending'
    expected = EXPECTED_HOURS.get(entry['id'], 24) * 3600
    last = entry['checked_at'] or entry['updated_at'] or 0
    if now - last > 3 * expected:
        return 'late'
    return 'ok'


def build_catalogs(raw, now):
    out = []
    for cid in CATALOG_ORDER:
        entry = NORMALIZERS[cid](raw.get(cid))
        if entry is None:
            continue
        entry['status'] = freshness(entry, now)
        out.append(entry)
    return out


def build_events(catalogs, av_status, now):
    """Recent things the firewall learned or did: catalogs updated and files the antivirus stopped, newest first."""
    events = []
    for c in catalogs:
        at = c.get('updated_at')
        if at and 0 <= now - at <= EVENT_WINDOW:
            events.append({'type': 'catalog_updated', 'at': at, 'catalog': c['id'], 'name': c['name'], 'version': c.get('version')})
    detections = av_status.get('detections') if isinstance(av_status, dict) else None
    for d in detections or []:
        at = _int(d.get('time')) if isinstance(d, dict) else None
        if at and 0 <= now - at <= EVENT_WINDOW:
            events.append({'type': 'file_blocked', 'at': at, 'reason': d.get('reason'), 'detail': str(d.get('detail', ''))[:120]})
    events.sort(key=lambda e: e['at'], reverse=True)
    return events[:MAX_EVENTS]


def build_layers(raw, modules):
    """One block per protection with its state and the counters that really exist (each counter says its time window)."""
    layers = {}
    web_rules = (raw.get('web_rules') or {}).get('values') if isinstance(raw.get('web_rules'), dict) else None
    insp = raw.get('web_inspection') if isinstance(raw.get('web_inspection'), dict) else {}
    av = raw.get('av') if isinstance(raw.get('av'), dict) else {}
    counters = av.get('counters') if isinstance(av.get('counters'), dict) else {}
    settings = raw.get('web_settings') if isinstance(raw.get('web_settings'), dict) else {}
    layers['web'] = {
        'present': web_rules is not None or bool(insp) or bool(av),
        'licensed': bool(modules.get('web')),
        'enabled': bool(settings.get('enabled')),
        'rules': len(web_rules) if web_rules is not None else None,
        'rules_enabled': sum(1 for r in web_rules or [] if r.get('enabled')) if web_rules is not None else None,
        'inspecting_rules': _int(insp.get('rules')),
        'proxy_running': insp.get('squid'),
        'redirect_active': insp.get('redirect'),
        'skipped_lists': insp.get('skipped') or [],
    }
    settings_av = av.get('settings') if isinstance(av.get('settings'), dict) else {}
    layers['av'] = {
        'present': bool(av),
        'licensed': bool(modules.get('av')),
        'enabled': bool(settings_av.get('enabled')),
        'degraded': bool(av.get('degraded')),
        'scanning': bool(settings_av.get('enabled')) and not av.get('not_scanning', False),
        'scanned': _int(counters.get('scanned')), 'infected': _int(counters.get('infected')), 'errors': _int(counters.get('errors')),
        'counters_since': 'service start',
    }
    snort = raw.get('snort') if isinstance(raw.get('snort'), dict) else {}
    layers['ips'] = {
        'present': bool(snort), 'licensed': bool(modules.get('ips')), 'enabled': bool(snort.get('enabled')),
        'events_24h': _int(snort.get('events')),
    }
    dpi_rules = (raw.get('dpi_rules') or {}).get('values') if isinstance(raw.get('dpi_rules'), dict) else None
    layers['dpi'] = {
        'present': dpi_rules is not None, 'licensed': bool(modules.get('dpi')),
        'rules': len(dpi_rules) if dpi_rules is not None else None,
        'rules_enabled': sum(1 for r in dpi_rules or [] if r.get('enabled')) if dpi_rules is not None else None,
    }
    ts = raw.get('threat_shield') if isinstance(raw.get('threat_shield'), dict) else {}
    layers['threat_shield'] = {
        'present': bool(ts), 'licensed': bool(modules.get('dpi') or modules.get('dns') or modules.get('geo')),
        'ip_status': ts.get('ip_status'), 'dns_status': ts.get('dns_status'),
        'ip_blocked_1h': _int(ts.get('ip_blocked_1h')),
    }
    return layers


def build_overview(raw, modules, now=None):
    now = int(now if now is not None else time.time())
    catalogs = build_catalogs(raw, now)
    current = sum(1 for c in catalogs if c['status'] == 'ok')
    counted = sum(1 for c in catalogs if c['status'] != 'unlicensed')
    layers = build_layers(raw, modules)
    return {
        'generated_at': now,
        'modules': {k: bool(v) for k, v in modules.items()},
        'catalogs': catalogs,
        'catalogs_current': current, 'catalogs_total': counted,
        'layers': layers,
        'events': build_events(catalogs, raw.get('av') if isinstance(raw.get('av'), dict) else {}, now),
        'sandbox': raw.get('sandbox') if isinstance(raw.get('sandbox'), dict) else None,
        'errors': raw.get('errors', []),
    }


# ---------------------------------------------------------------- gathering (runs the commands; not unit tested)

def _run_json(cmd, stdin=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=COMMAND_TIMEOUT, input=stdin)
        return json.loads(p.stdout) if p.stdout.strip() else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _ubus(obj, method, payload=None):
    if not os.path.exists('/bin/ubus'):
        return None
    return _run_json(['/bin/ubus', 'call', obj, method, json.dumps(payload or {})])


def _client(path, *args):
    return _run_json([path] + list(args)) if os.path.exists(path) else None


def gather(modules_fn):
    errors = []
    raw = {}

    def part(name, fn):
        try:
            raw[name] = fn()
        except Exception:
            raw[name] = None
            errors.append(name)

    part('dpi', lambda: _client('/usr/sbin/nexwall-dpi-catalog', 'status', '--json'))
    part('ips', lambda: _client('/usr/sbin/nexwall-ips-rules', 'status', '--json'))
    part('threat_feeds', lambda: _client('/usr/sbin/nexwall-threat-feeds', 'status', '--json'))
    part('web', lambda: _ubus('ns.webprotection', 'get-catalog-status'))
    part('av', lambda: _ubus('ns.webprotection', 'get-av-status'))
    part('web_rules', lambda: _ubus('ns.webprotection', 'list-rules'))
    part('web_settings', lambda: _ubus('ns.webprotection', 'get-settings'))
    part('web_inspection', lambda: _ubus('ns.webprotection', 'get-inspection-status'))
    part('snort', lambda: _ubus('ns.snort', 'status'))
    part('dpi_rules', lambda: _ubus('ns.dpi', 'list-rules'))

    def threat_shield():
        def svc(name):
            out = _ubus('ns.dashboard', 'service-status', {'service': name})
            return (out or {}).get('result', {}).get('status')
        blocked = (_ubus('ns.dashboard', 'counter', {'service': 'threat_shield_ip'}) or {}).get('result', {}).get('count')
        return {'ip_status': svc('threat_shield_ip'), 'dns_status': svc('threat_shield_dns'), 'ip_blocked_1h': blocked}

    part('threat_shield', threat_shield)
    raw['errors'] = errors
    return raw, modules_fn()


def overview(modules_fn, now=None, cache=True):
    """The overview, cached for a few seconds so several open dashboards cost one set of commands."""
    now = int(now if now is not None else time.time())
    if cache:
        try:
            if now - os.path.getmtime(CACHE_FILE) < CACHE_SECONDS:
                with open(CACHE_FILE) as f:
                    return json.load(f)
        except (OSError, ValueError):
            pass
    raw, modules = gather(modules_fn)
    result = build_overview(raw, modules, now)
    if cache:
        try:
            tmp = CACHE_FILE + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(result, f)
            os.replace(tmp, CACHE_FILE)
        except OSError:
            pass
    return result
