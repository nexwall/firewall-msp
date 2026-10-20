#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

import json
import os
import time
from datetime import datetime

from nethsec import threats

NOW = int(datetime(2026, 10, 8, 12, 0, 0).timestamp())


def mem(tmp_path):
    return threats.connect(str(tmp_path / 'events.db'))


def test_syslog_banip_drop_and_country(tmp_path):
    line = 'Oct  8 11:30:05 FW kernel: banIP/malware/drop/inbound IN=eth1 SRC=45.1.2.3 DST=192.168.1.20 PROTO=TCP'
    ev = threats.parse_syslog_line(line, NOW)
    assert ev['layer'] == 'threat_shield' and ev['client'] == '192.168.1.20' and ev['remote'] == '45.1.2.3'
    assert ev['reason'] == 'malware'
    geo = 'Oct  8 11:31:00 FW kernel: banIP/country/drop/outbound/country SRC=192.168.1.20 DST=8.8.4.4'
    ev = threats.parse_syslog_line(geo, NOW)
    assert ev['layer'] == 'geo' and ev['client'] == '192.168.1.20' and ev['remote'] == '8.8.4.4'


def test_syslog_dns_block_ignores_reverse_and_local(tmp_path):
    ok = 'Oct  8 11:30:05 FW dnsmasq[1]: config bad.example.com is NXDOMAIN'
    assert threats.parse_syslog_line(ok, NOW)['layer'] == 'dns'
    assert threats.parse_syslog_line('Oct  8 11:30:05 FW dnsmasq[1]: config 4.3.2.1.in-addr.arpa is NXDOMAIN', NOW) is None
    assert threats.parse_syslog_line('Oct  8 11:30:05 FW dnsmasq[1]: config printer is NXDOMAIN', NOW) is None


def test_syslog_year_rollover():
    ts = threats.syslog_time('Dec 31 23:59:00 FW x', int(datetime(2027, 1, 1, 0, 5, 0).timestamp()))
    assert datetime.fromtimestamp(ts).year == 2026


def test_snort_alert_severity_and_parties():
    line = json.dumps({'timestamp': '10/08-11:00:00.1', 'src_ap': '45.9.9.9:4444', 'dst_ap': '192.168.1.5:445',
                       'priority': 1, 'msg': 'ET EXPLOIT test', 'class': 'attempted-admin', 'action': 'allow'})
    ev = threats.parse_snort_alert(line, NOW)
    assert ev['layer'] == 'ips' and ev['severity'] == 'critical' and ev['action'] == 'detected'
    assert ev['client'] == '192.168.1.5' and ev['remote'] == '45.9.9.9'
    assert threats.parse_snort_alert('not json', NOW) is None


def test_av_detection_skips_engine_down():
    assert threats.parse_av_detection({'time': 5, 'reason': 'engine-down'}) is None
    ev = threats.parse_av_detection({'time': 5, 'client': '10.0.0.8', 'reason': 'virus', 'detail': 'Eicar'})
    assert ev['layer'] == 'antivirus' and ev['client'] == '10.0.0.8'


def test_squid_denied_only():
    denied = '1791427717.9 0 192.168.1.30 TCP_DENIED/403 3100 GET http://bad.example.net/x - HIER_NONE/- text/html'
    assert threats.parse_squid_line(denied)['remote'] == 'bad.example.net'
    assert threats.parse_squid_line('1791427717.9 0 192.168.1.30 TCP_MISS/200 10 GET http://a.b/ - HIER_NONE/- t') is None
    assert threats.parse_squid_line('1791427717.9 0 127.0.0.1 TCP_DENIED/403 10 GET http://x/squid-internal-mgr/info - - t') is None


def test_same_minute_events_are_one_row_with_a_count(tmp_path):
    db = mem(tmp_path)
    ev = {'ts': NOW, 'layer': 'web', 'action': 'blocked', 'severity': 'low', 'client': '10.0.0.2', 'remote': 'x.com', 'reason': 'web policy'}
    threats.add_events(db, [ev, dict(ev, ts=NOW + 10), dict(ev, remote='y.com')])
    rows = db.execute('SELECT remote, count FROM events ORDER BY remote').fetchall()
    assert rows == [('x.com', 2), ('y.com', 1)]


def test_read_new_lines_follows_the_file_and_survives_rotation(tmp_path):
    db = mem(tmp_path)
    log = tmp_path / 'log'
    log.write_text('a\nb\n')
    assert threats.read_new_lines(db, 's', str(log)) == ['a', 'b']
    with open(log, 'a') as fh:
        fh.write('c\npartial')
    assert threats.read_new_lines(db, 's', str(log)) == ['c']
    os.remove(log)
    log.write_text('new\n')
    assert threats.read_new_lines(db, 's', str(log)) == ['new']


def test_retention_prunes_old_events(tmp_path):
    db = mem(tmp_path)
    base = {'layer': 'dns', 'action': 'blocked', 'severity': 'low', 'client': '', 'remote': 'x.com', 'reason': 'dns filter'}
    threats.add_events(db, [dict(base, ts=NOW - 40 * 86400), dict(base, ts=NOW - 86400, remote='y.com')])
    threats.prune(db, NOW)
    assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 1


def test_summary_counts_compares_and_ranks_devices(tmp_path):
    db = mem(tmp_path)
    base = {'action': 'blocked', 'severity': 'low', 'reason': 'r'}
    threats.add_events(db, [
        dict(base, ts=NOW - 600, layer='antivirus', severity='high', client='192.168.1.7', remote='', reason='virus'),
        dict(base, ts=NOW - 700, layer='web', client='192.168.1.8', remote='bad.com'),
        dict(base, ts=NOW - 800, layer='web', client='192.168.1.8', remote='bad.com'),
        dict(base, ts=NOW - 86400 - 100, layer='dns', client='', remote='old.com'),
    ])
    out = threats.summary(db, days=1, now=NOW)
    assert out['total'] == 3
    assert out['by_layer']['antivirus'] == 1 and out['by_layer']['web'] == 2
    assert out['previous_total'] == 1
    assert out['at_risk'][0]['device'] == '192.168.1.7'  # one antivirus detection (10 x 2) outranks two web blocks
    assert out['top_sources'][0] == {'id': 'bad.com', 'count': 2}
    assert out['weights']['antivirus'] == 10


def test_events_filter_and_search(tmp_path):
    db = mem(tmp_path)
    base = {'action': 'blocked', 'severity': 'low', 'reason': 'r', 'client': '10.0.0.2'}
    threats.add_events(db, [dict(base, ts=NOW - 60, layer='web', remote='a.com'), dict(base, ts=NOW - 120, layer='dns', remote='b.com')])
    assert threats.events(db, layer='dns', now=NOW)['total'] == 1
    assert threats.events(db, search='a.com', now=NOW)['events'][0]['remote'] == 'a.com'
    assert threats.events(db, limit=1, now=NOW)['total'] == 2


def test_syslog_category_block_page():
    line = 'Oct  8 11:30:05 FW nexwall-av[88]: page-blocked client=192.168.1.20 host=WWW.Bet.Example category=gambling rule=Staff rule 1'
    ev = threats.parse_syslog_line(line, NOW)
    assert ev['layer'] == 'web' and ev['client'] == '192.168.1.20' and ev['remote'] == 'www.bet.example'
    assert ev['reason'] == 'category: gambling' and ev['detail'] == 'rule Staff rule 1'


def test_block_page_reference_is_kept_so_the_event_can_be_found_by_it():
    line = 'Oct  8 11:30:05 FW nexwall-av[88]: page-blocked client=192.168.1.20 host=casadeapostas.com category=gambling ref=BCCFD8F9 rule=BP test'
    ev = threats.parse_syslog_line(line, NOW)
    assert ev['detail'] == 'rule BP test ref BCCFD8F9'


def test_syslog_content_filter_blocked_and_logged():
    line = 'Oct  8 11:30:05 FW nexwall-av[88]: content-blocked client=192.168.1.20 host=Bets.Example category=gambling score=87 profile=school rule=Content test'
    ev = threats.parse_syslog_line(line, NOW)
    assert ev['layer'] == 'web' and ev['action'] == 'blocked' and ev['client'] == '192.168.1.20' and ev['remote'] == 'bets.example'
    assert ev['reason'] == 'content: gambling' and ev['detail'] == 'rule Content test, profile school, score 87'
    logged = threats.parse_syslog_line(line.replace('content-blocked', 'content-logged'), NOW)
    assert logged['action'] == 'detected' and logged['reason'] == 'content: gambling'


ATP_LINE = json.dumps({'layer': 'atp', 'kind': 'flow-behaviour', 'host': '192.168.1.50', 'score': 0.9991, 'level': 'high', 'model': 'm', 'version': '1', 'window': 900,
                       'ts': NOW - 60, 'evidence': ['contacts a destination at regular intervals (regularity 0.97)', '3 DNS name(s) with a generated look'],
                       'indicators': [{'type': 'ip', 'value': '203.0.113.9', 'port': 8443, 'beacon': 0.97}]})


def test_atp_event_is_advisory_with_the_evidence(tmp_path):
    ev = threats.parse_atp_event(ATP_LINE)
    assert ev['layer'] == 'atp' and ev['action'] == 'detected' and ev['severity'] == 'high'
    assert ev['client'] == '192.168.1.50' and ev['remote'] == '203.0.113.9'
    assert 'regular intervals' in ev['detail'] and 'score 0.9991' in ev['detail']
    review = json.dumps(dict(json.loads(ATP_LINE), level='review', indicators=[]))
    assert threats.parse_atp_event(review)['severity'] == 'medium' and threats.parse_atp_event(review)['remote'] == ''


def test_atp_event_rejects_what_is_not_an_event():
    for bad in ('', 'not json', '[]', json.dumps({'layer': 'atp', 'host': 'h', 'level': 'normal', 'ts': 1}),
                json.dumps({'layer': 'ips', 'host': 'h', 'level': 'high', 'ts': 1}), json.dumps({'layer': 'atp', 'level': 'high', 'ts': 1}),
                json.dumps({'layer': 'atp', 'host': 'h', 'level': 'high'})):
        assert threats.parse_atp_event(bad) is None


def test_collect_reads_the_atp_file_and_the_layer_is_counted(tmp_path, monkeypatch):
    path = tmp_path / 'events.jsonl'
    path.write_text(ATP_LINE + '\n' + 'torn line without end')
    for name in ('SYSLOG', 'SQUID_LOG', 'AV_DETECTIONS'):
        monkeypatch.setattr(threats, name, str(tmp_path / 'none'))
    monkeypatch.setattr(threats, 'SNORT_DIR', str(tmp_path / 'nosnort'))
    monkeypatch.setattr(threats, 'ATP_EVENTS', str(path))
    db = mem(tmp_path)
    assert threats.collect(db, now=NOW)['atp'] == 1
    assert threats.collect(db, now=NOW)['atp'] == 0                       # the cursor moved on
    assert threats.summary(db, days=1, now=NOW)['by_layer']['atp'] == 1
    assert 'atp' in threats.LAYERS
