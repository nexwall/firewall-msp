import os
import time

from nethsec import atp

NOW = 1_800_000_000
GOOD = {'enabled': True, 'entitled': True, 'alive': True, 'age': 20, 'interval': 60, 'state': 'scoring', 'dns_view': ['br-lan'], 'last_error': None,
        'last_error_ts': None, 'model_stale': False}


def st(**kw):
    return dict(GOOD, **kw)


def test_a_healthy_scorer_is_running():
    assert atp.assess_scorer(st(), NOW) == {'state': 'running', 'reasons': []}


def test_off_stopped_and_not_in_plan():
    assert atp.assess_scorer(st(enabled=False), NOW)['state'] == 'off'
    assert atp.assess_scorer(st(entitled=False), NOW)['state'] == 'not_in_plan'
    assert atp.assess_scorer(st(entitled=False, enabled=False), NOW)['state'] == 'not_in_plan'
    assert atp.assess_scorer(st(alive=False), NOW) == {'state': 'stopped', 'reasons': ['service_not_running']}
    assert atp.assess_scorer(st(age=5 * 60 + 1), NOW)['state'] == 'stopped'           # the status file stopped being rewritten (5 cycles)
    assert atp.assess_scorer(st(age=5 * 60 - 1), NOW)['state'] == 'running'
    assert atp.assess_scorer(st(state='not_running'), NOW)['state'] == 'stopped'
    assert atp.assess_scorer({}, NOW)['state'] == 'off'                                # nothing known and not switched on: off, not "stopped"
    assert atp.assess_scorer(None, NOW)['state'] == 'off'


def test_the_interval_of_the_service_sets_when_it_is_late():
    assert atp.assess_scorer(st(interval=120, age=500), NOW)['state'] == 'running'
    assert atp.assess_scorer(st(interval=120, age=601), NOW)['state'] == 'stopped'


def test_degraded_names_what_is_wrong():
    assert atp.assess_scorer(st(state='no_model'), NOW) == {'state': 'degraded', 'reasons': ['no_model']}
    assert atp.assess_scorer(st(dns_view=[]), NOW) == {'state': 'degraded', 'reasons': ['no_dns_view']}
    assert atp.assess_scorer(st(model_stale=True), NOW)['reasons'] == ['model_stale']
    recent = st(last_error='ns.flows did not answer', last_error_ts=NOW - 60)
    assert atp.assess_scorer(recent, NOW) == {'state': 'degraded', 'reasons': ['recent_error']}
    old = st(last_error='ns.flows did not answer', last_error_ts=NOW - 3600)
    assert atp.assess_scorer(old, NOW)['state'] == 'running'                           # an old error is history
    many = atp.assess_scorer(st(state='no_model', dns_view=[], model_stale=True), NOW)
    assert many['state'] == 'degraded' and set(many['reasons']) == {'no_model', 'no_dns_view', 'model_stale'}


FEEDS = {'license_state': 'subscribed', 'version': '2026.10.20.1', 'last_error': None,
         'categories': [{'id': 'atp_ip', 'kind': 'ip', 'enabled': True, 'downloaded': True, 'count': 3},
                        {'id': 'atp_dns', 'kind': 'dns', 'enabled': True, 'downloaded': True, 'count': 7},
                        {'id': 'malware', 'kind': 'dns', 'enabled': True, 'downloaded': True, 'count': 100}]}


def test_collective_running_off_and_not_in_plan():
    cfg = {'collective': True, 'share': True}
    assert atp.assess_collective(cfg, FEEDS, {'entitled': True}) == {'state': 'running', 'reasons': []}
    assert atp.assess_collective({'collective': False}, FEEDS, {})['state'] == 'off'
    assert atp.assess_collective(cfg, dict(FEEDS, license_state='unlicensed'), {})['state'] == 'not_in_plan'
    assert atp.assess_collective(cfg, FEEDS, {}, modules={'atp': False})['state'] == 'not_in_plan'


def test_collective_degraded_reasons():
    cfg = {'collective': True, 'share': True}
    assert atp.assess_collective(cfg, {'license_state': 'trial'}, {}) == {'state': 'degraded', 'reasons': ['no_bundle']}
    assert atp.assess_collective(cfg, {'version': 'v', 'categories': [{'id': 'malware'}]}, {})['reasons'] == ['no_categories']
    off = dict(FEEDS, categories=[dict(FEEDS['categories'][0], enabled=False)] + FEEDS['categories'][1:])
    assert atp.assess_collective(cfg, off, {})['reasons'] == ['list_off:atp_ip']
    miss = dict(FEEDS, categories=[dict(FEEDS['categories'][0], downloaded=False)] + FEEDS['categories'][1:])
    assert atp.assess_collective(cfg, miss, {})['reasons'] == ['list_missing:atp_ip']
    assert atp.assess_collective(cfg, dict(FEEDS, last_error='x'), {})['reasons'] == ['update_error']
    assert atp.assess_collective(cfg, FEEDS, {'entitled': True, 'report': {'last_error': 'down'}})['reasons'] == ['report_error']
    # a report that fails does not matter when sharing is off
    assert atp.assess_collective({'collective': True, 'share': False}, FEEDS, {'report': {'last_error': 'down'}})['state'] == 'running'


def test_lists_summary_keeps_only_the_shared_lists():
    s = atp.lists_summary(FEEDS)
    assert s['version'] == '2026.10.20.1' and set(s['lists']) == {'atp_ip', 'atp_dns'} and s['lists']['atp_dns']['entries'] == 7
    assert atp.lists_summary(None)['lists'] == {}


def test_derive_status_checks_the_process_and_the_age(monkeypatch):
    now = int(time.time())
    out = atp.derive_status({'pid': os.getpid(), 'ts': now - 30})
    assert out['alive'] is True and 29 <= out['age'] <= 35
    gone = atp.derive_status({'pid': 2 ** 22 + 7, 'ts': now})
    assert gone['alive'] is False
    assert atp.derive_status({'state': 'not_running'}) == {'state': 'not_running', 'alive': False, 'age': None}
    assert atp.derive_status(None)['alive'] is False


STAT = 'cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 50 0 50 350 50 0 0 0 0 0\ncpu1 50 0 50 350 50 0 0 0 0 0\n'


def make_proc(tmp_path, pid=123, ticks=(40, 10)):
    d = tmp_path / str(pid)
    (d / 'task' / str(pid)).mkdir(parents=True)
    (d / 'status').write_text('Name:\tpython3\nVmRSS:\t   24100 kB\nThreads:\t3\n')
    (d / 'task' / str(pid) / 'stat').write_text('%d (python3) S 1 1 1 0 -1 0 0 0 0 0 %d %d 0 0 20 0 3 0 1 1 1' % (pid, ticks[0], ticks[1]))
    (tmp_path / 'stat').write_text(STAT)
    (tmp_path / 'meminfo').write_text('MemTotal: 4000000 kB\nMemAvailable: 3000000 kB\n')


def test_collect_reads_the_process_of_the_pid_the_scorer_wrote(tmp_path):
    make_proc(tmp_path)
    status = {'pid': 123, 'cycles': 10, 'flows_read': 200, 'dns_records': 50, 'events_total': 2, 'hosts': 8, 'last_cycle_ms': 31.5, 'interval': 60,
              'dns_view': ['br-lan'], 'model': 'm', 'model_version': '1'}
    m = atp.collect(status, proc=str(tmp_path), sample=0, clock_ticks=100)
    assert m['engines']['atp']['running'] is True and m['engines']['atp']['rss_kib'] == 24100 and m['engines']['atp']['threads'] == 3
    assert m['memory']['used_pct'] == 25.0 and m['cpu']['cores'] == 2
    assert m['counters'] == {'cycles': 10, 'flows_read': 200, 'dns_records': 50, 'events_total': 2}
    assert m['scorer']['hosts'] == 8 and m['scorer']['dns_view'] == ['br-lan']


def test_collect_without_a_process(tmp_path):
    make_proc(tmp_path)
    m = atp.collect({'pid': 999}, proc=str(tmp_path), sample=0, clock_ticks=100)
    assert m['engines']['atp'] == {'running': False, 'cpu_pct': 0.0, 'rss_kib': 0, 'threads': 0}
    assert atp.collect(None, proc=str(tmp_path), sample=0, clock_ticks=100)['engines']['atp']['running'] is False


def test_updating_finds_a_running_command_line(tmp_path):
    d = tmp_path / '321'
    d.mkdir()
    (d / 'cmdline').write_bytes(b'/usr/bin/python3\0/usr/sbin/nexwall-atp\0update\0--force\0')
    (tmp_path / '322').mkdir()
    (tmp_path / '322' / 'cmdline').write_bytes(b'/usr/bin/python3\0/usr/sbin/nexwall-atp\0daemon\0')
    assert atp.updating('/usr/sbin/nexwall-atp', 'update', str(tmp_path)) is True
    assert atp.updating('/usr/sbin/nexwall-atp', 'report', str(tmp_path)) is False
    assert atp.updating('/usr/sbin/nexwall-threat-feeds', 'update', str(tmp_path)) is False


def test_update_hours_offered():
    assert atp.UPDATE_HOURS == (1, 3, 6, 12, 24)


def test_a_shared_list_in_a_service_that_is_off_is_degraded():
    cfg = {'collective': True, 'share': False}
    assert atp.assess_collective(cfg, FEEDS, {}, None, {'ip': True, 'dns': True})['state'] == 'running'
    assert atp.assess_collective(cfg, FEEDS, {}, None, {'ip': None, 'dns': None})['state'] == 'running'        # unknown: no complaint
    r = atp.assess_collective(cfg, FEEDS, {}, None, {'ip': False, 'dns': True})
    assert r == {'state': 'degraded', 'reasons': ['service_off:ip']}
    assert atp.assess_collective(cfg, FEEDS, {}, None, {'ip': False, 'dns': False})['reasons'] == ['service_off:ip', 'service_off:dns'] or \
        set(atp.assess_collective(cfg, FEEDS, {}, None, {'ip': False, 'dns': False})['reasons']) == {'service_off:ip', 'service_off:dns'}


def test_services_come_from_the_switches_in_the_configuration():
    values = {'banip.global.ban_enabled': '0', 'adblock.global.adb_enabled': '1'}
    assert atp.services_from_uci(lambda k: values.get(k, '')) == {'ip': False, 'dns': True}
    assert atp.services_from_uci(lambda k: '') == {'ip': False, 'dns': False}               # an option that is not set is off
    assert atp.services_from_uci(lambda k: 'x') == {'ip': None, 'dns': None}                # unreadable: unknown, no complaint


def test_read_services_survives_a_missing_uci(monkeypatch):
    monkeypatch.setattr(atp.subprocess, 'run', lambda *a, **k: (_ for _ in ()).throw(OSError('no uci')))
    assert atp.read_services() == {'ip': None, 'dns': None}
