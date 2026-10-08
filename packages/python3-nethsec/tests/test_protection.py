import os

from nethsec import protection as p

NOW = 1_800_000_000
H = 3600


def raw_ok():
    return {
        'dpi': {'entitled': True, 'installed_version': '2026.10.04', 'installed_at': NOW - 3 * 86400, 'last_check': NOW - 2 * H,
                'counts': {'applications': 5200, 'domains': 120000}, 'source': 'nexwall', 'last_result': 'up to date', 'last_error': None},
        'ips': {'license_state': 'subscribed', 'installed_version': '2026.10.06', 'last_check': NOW - 600,
                'counts': {'rules': 38400}, 'policy': 'balanced', 'last_result': 'downloaded 2026.10.06', 'last_error': None},
        'threat_feeds': {'license_state': 'subscribed', 'version': '2026.10.07', 'last_check': NOW - H,
                         'counts': {'ip': 412300, 'dns': 2100000}, 'last_result': 'ok'},
        'web': {'license_state': 'subscribed', 'version': '2026.10.06.1', 'installed_at': NOW - 14 * H, 'last_check': NOW - 2 * H,
                'domains': 4890000, 'installed': ['adult', 'malware'], 'skipped': {'ut1-adult': 1}, 'memory_mb': 700, 'last_error': None},
        'av': {'licensed': True, 'yara_version': '2026.10.06.1',
               'signatures': {'main': NOW - 5 * 86400, 'daily': NOW - 3 * H, 'bytecode': NOW - 4 * H},
               'last_check': NOW - 3 * H, 'clamav_updated': NOW - 3 * H, 'last_error': None,
               'settings': {'enabled': True}, 'degraded': False, 'not_scanning': False,
               'counters': {'scanned': 3912, 'infected': 2, 'errors': 0},
               'detections': [{'time': NOW - 600, 'reason': 'infected', 'detail': 'clamav: Eicar-Test-Signature'},
                              {'time': NOW - 3 * 86400, 'reason': 'infected', 'detail': 'old'}]},
        'web_rules': {'values': [{'enabled': True}, {'enabled': False}, {'enabled': True}]},
        'web_settings': {'enabled': True},
        'web_inspection': {'rules': 2, 'squid': True, 'redirect': True, 'skipped': [{'list': 'adult'}]},
        'snort': {'enabled': True, 'events': 87},
        'dpi_rules': {'values': [{'enabled': True}] * 4},
        'threat_shield': {'ip_status': 'ok', 'dns_status': 'ok', 'ip_blocked_1h': 566},
        'errors': [],
    }


MODULES = {'dpi': True, 'ips': True, 'dns': True, 'geo': True, 'web': True, 'av': True, 'atp': True}


def status_map(o):
    return {c['id']: c['status'] for c in o['catalogs']}


def test_catalogs_are_normalised_and_ordered():
    o = p.build_overview(raw_ok(), MODULES, NOW)
    assert [c['id'] for c in o['catalogs']] == ['threat_feeds', 'ips', 'web', 'av', 'dpi']
    web = next(c for c in o['catalogs'] if c['id'] == 'web')
    assert web['entries'] == 4890000 and web['entries_unit'] == 'domains'
    assert web['detail']['lists'] == 2 and web['detail']['skipped'] == ['ut1-adult']
    ips = next(c for c in o['catalogs'] if c['id'] == 'ips')
    assert ips['entries'] == 38400 and ips['version'] == '2026.10.06'
    feeds = next(c for c in o['catalogs'] if c['id'] == 'threat_feeds')
    assert feeds['entries'] == 412300 + 2100000
    av = next(c for c in o['catalogs'] if c['id'] == 'av')
    assert av['updated_at'] == NOW - 3 * H


def test_freshness_rules():
    o = p.build_overview(raw_ok(), MODULES, NOW)
    assert status_map(o) == {'threat_feeds': 'ok', 'ips': 'ok', 'web': 'ok', 'av': 'ok', 'dpi': 'ok'}
    assert o['catalogs_current'] == 5 and o['catalogs_total'] == 5
    late = raw_ok()
    late['ips']['last_check'] = NOW - 4 * H            # checked every 30 minutes: 4 hours is late
    late['dpi']['last_check'] = NOW - 4 * 86400        # daily: 4 days is late
    st = status_map(p.build_overview(late, MODULES, NOW))
    assert st['ips'] == 'late' and st['dpi'] == 'late' and st['web'] == 'ok'
    err = raw_ok()
    err['web']['last_error'] = 'manifest request failed: HTTP 401'
    assert status_map(p.build_overview(err, MODULES, NOW))['web'] == 'error'


def test_unlicensed_and_pending_catalogs_are_not_counted_as_current():
    raw = raw_ok()
    raw['web']['license_state'] = 'unlicensed'
    raw['av'] = {'licensed': True, 'settings': {'enabled': True}}
    o = p.build_overview(raw, MODULES, NOW)
    st = status_map(o)
    assert st['web'] == 'unlicensed' and st['av'] == 'pending'
    assert o['catalogs_total'] == 4 and o['catalogs_current'] == 3


def test_missing_sources_are_left_out_not_invented():
    o = p.build_overview({'errors': ['web']}, {}, NOW)
    assert o['catalogs'] == [] and o['events'] == [] and o['sandbox'] is None and o['errors'] == ['web']
    assert not o['layers']['web']['present'] and not o['layers']['ips']['present'] and not o['layers']['av']['present']
    assert o['layers']['ips']['events_24h'] is None


def test_layers_carry_only_real_counters():
    L = p.build_overview(raw_ok(), MODULES, NOW)['layers']
    assert L['ips'] == {'present': True, 'licensed': True, 'enabled': True, 'events_24h': 87}
    assert L['av']['scanned'] == 3912 and L['av']['infected'] == 2 and L['av']['scanning']
    assert L['av']['counters_since'] == 'service start'
    assert L['web']['rules'] == 3 and L['web']['rules_enabled'] == 2 and L['web']['inspecting_rules'] == 2 and L['web']['proxy_running']
    assert L['dpi']['rules'] == 4
    assert L['threat_shield']['ip_blocked_1h'] == 566 and L['threat_shield']['ip_status'] == 'ok'


def test_events_are_recent_sorted_and_capped():
    o = p.build_overview(raw_ok(), MODULES, NOW)
    details = [e.get('detail') for e in o['events'] if e['type'] == 'file_blocked']
    assert details == ['clamav: Eicar-Test-Signature']                          # the 3 days old detection is not shown
    assert all(NOW - e['at'] <= 86400 for e in o['events'])
    assert [e['at'] for e in o['events']] == sorted((e['at'] for e in o['events']), reverse=True)
    many = raw_ok()
    many['av']['detections'] = [{'time': NOW - i, 'reason': 'infected', 'detail': 'x'} for i in range(30)]
    assert len(p.build_overview(many, MODULES, NOW)['events']) == p.MAX_EVENTS


def test_degraded_antivirus_is_visible():
    raw = raw_ok()
    raw['av'].update({'degraded': True, 'not_scanning': True})
    av = p.build_overview(raw, MODULES, NOW)['layers']['av']
    assert av['degraded'] and not av['scanning']


def test_count_helpers():
    assert p._total({'a': 2, 'b': 3, 'c': 'x'}) == 5 and p._total(7) == 7 and p._total(None) is None and p._total(True) is None
    assert p._int('12') == 12 and p._int(None) is None and p._int('x') is None


def test_cache_is_used_for_a_few_seconds(tmp_path, monkeypatch):
    monkeypatch.setattr(p, 'CACHE_FILE', str(tmp_path / 'c.json'))
    calls = []

    def fake(fn):
        calls.append(1)
        return raw_ok(), MODULES

    monkeypatch.setattr(p, 'gather', fake)
    first = p.overview(lambda: MODULES, now=NOW)
    os.utime(p.CACHE_FILE, (NOW, NOW))                  # the cache age is read from the file time
    second = p.overview(lambda: MODULES, now=NOW + 1)
    assert len(calls) == 1 and first == second
    os.utime(p.CACHE_FILE, (NOW - 100, NOW - 100))
    p.overview(lambda: MODULES, now=NOW)
    assert len(calls) == 2


def test_sandbox_block_only_while_the_unit_uses_it():
    off = {'enabled': False, 'entitled': True, 'analysed': 3}
    outside = {'enabled': True, 'entitled': False, 'analysed': 3}
    on = {'enabled': True, 'entitled': True, 'analysed': 3, 'queued': 1, 'malicious': 1, 'suspicious': 0, 'advisory': True,
          'gateway': 'https://secret.example', 'machines': []}
    assert p.normalize_sandbox(None) is None and p.normalize_sandbox(off) is None and p.normalize_sandbox(outside) is None
    shown = p.normalize_sandbox(on)
    assert shown['analysed'] == 3 and shown['advisory'] is True and 'gateway' not in shown
    assert p.build_overview({'sandbox': on}, {}, now=1)['sandbox']['malicious'] == 1
    assert p.build_overview({'sandbox': off}, {}, now=1)['sandbox'] is None
