#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Threat events of the firewall, kept on disk for 35 days so Traffic Analytics and the executive report do not depend on the
system log (which lives in RAM and starts empty after a reboot).

One event record for every protection: time, layer, action, severity, internal device, remote party, reason, detail.
``collect`` reads what is new in the sources the protections already write (system log, Snort alerts, antivirus detections,
Squid denials), ``summary`` and ``events`` read the store. The parsers are pure functions (unit tested).
"""

import ipaddress
import json
import os
import re
import sqlite3
import time
from collections import defaultdict
from datetime import datetime

DB_PATH = '/mnt/data/threats/events.db'
RETENTION_DAYS = 35
MAX_READ_BYTES = 8 * 1024 * 1024
SYSLOG = '/var/log/messages'
SNORT_DIR = '/var/log/snort'
AV_DETECTIONS = '/var/lib/nexwall-av/detections.json'
SQUID_LOG = '/var/log/squid/access.log'

LAYERS = ['threat_shield', 'geo', 'dns', 'ips', 'web', 'antivirus', 'sandbox']
SEVERITIES = ['low', 'medium', 'high', 'critical']

# Weights of the "devices at risk" list. They are printed in the executive report: no hidden score.
RISK_WEIGHTS = {
    'antivirus': 10,
    'sandbox': 15,
    'ips': 5,
    'threat_shield': 2,
    'web': 1,
    'dns': 1,
    'geo': 1,
}
SEVERITY_FACTOR = {'low': 1, 'medium': 1, 'high': 2, 'critical': 3}

_MONTHS = {m: i + 1 for i, m in enumerate(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'])}
_SYSLOG_TS = re.compile(r'^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) ')
_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


# ---------------------------------------------------------------- parsers (pure)

def is_internal(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def split_parties(src, dst, outbound=None):
    """(device, remote): the internal address is the device, the other one the remote party."""
    if outbound is True:
        return src, dst
    if outbound is False:
        return dst, src
    if is_internal(src) and not is_internal(dst):
        return src, dst
    if is_internal(dst) and not is_internal(src):
        return dst, src
    return src, dst


def syslog_time(line, now=None):
    """Epoch of a syslog line ('Oct  8 02:34:00 ...'); the year is the current one, or the previous one around new year."""
    m = _SYSLOG_TS.match(line)
    if not m or m.group(1) not in _MONTHS:
        return None
    now = now or time.time()
    year = datetime.fromtimestamp(now).year
    try:
        stamp = datetime(year, _MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))).timestamp()
    except ValueError:
        return None
    if stamp > now + 86400:
        stamp = datetime(year - 1, _MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))).timestamp()
    return int(stamp)


def _field(line, name):
    m = re.search(r'\b%s=(\S+)' % name, line)
    return m.group(1) if m else None


def parse_syslog_line(line, now=None):
    """Event of one system log line, or None. Handles the banIP drops (Threat Shield lists and country blocks), the banIP
    attacker bans and the DNS filter answers."""
    ts = syslog_time(line, now)
    if ts is None:
        return None
    m = re.search(r'banIP/([A-Za-z0-9_-]+)/(drop|reject)/(inbound|outbound|forwardwan|forward|[a-z]+)?/?(country)?', line)
    if m and 'banIP' in line:
        src, dst = _field(line, 'SRC'), _field(line, 'DST')
        if src or dst:
            outbound = '/outbound/' in line or None
            if outbound is None and '/inbound/' in line:
                outbound = False
            device, remote = split_parties(src or '', dst or '', outbound)
            geo = '/country' in line
            return {
                'ts': ts, 'layer': 'geo' if geo else 'threat_shield', 'action': 'blocked', 'severity': 'low' if geo else 'medium',
                'client': device, 'remote': remote, 'reason': m.group(1), 'detail': '%s %s' % (m.group(2), m.group(3) or ''),
            }
    m = re.search(r'banIP.*add IP ([0-9.]+)', line)
    if m:
        return {'ts': ts, 'layer': 'threat_shield', 'action': 'blocked', 'severity': 'high', 'client': '', 'remote': m.group(1),
                'reason': 'attacker', 'detail': 'address banned after repeated attacks'}
    m = re.search(r'dnsmasq.*config (\S+) is NXDOMAIN', line)
    if m:
        domain = m.group(1).lower()
        if re.fullmatch(r'[0-9.:a-f]+', domain) or domain.endswith('.arpa') or '.' not in domain:
            return None
        return {'ts': ts, 'layer': 'dns', 'action': 'blocked', 'severity': 'low', 'client': '', 'remote': domain,
                'reason': 'dns filter', 'detail': ''}
    return None


def _snort_time(value, now=None):
    # alert_json: "10/08-02:34:00.123456" (local time, no year)
    m = re.match(r'(\d{1,2})/(\d{1,2})(?:/(\d{2,4}))?-(\d{2}):(\d{2}):(\d{2})', value or '')
    if not m:
        return None
    now = now or time.time()
    year = datetime.fromtimestamp(now).year
    try:
        stamp = datetime(year, int(m.group(1)), int(m.group(2)), int(m.group(4)), int(m.group(5)), int(m.group(6))).timestamp()
    except ValueError:
        return None
    if stamp > now + 86400:
        stamp = datetime(year - 1, int(m.group(1)), int(m.group(2)), int(m.group(4)), int(m.group(5)), int(m.group(6))).timestamp()
    return int(stamp)


def _strip_port(addr):
    addr = addr or ''
    if addr.count(':') == 1:
        return addr.split(':')[0]
    if addr.startswith('[') and ']' in addr:
        return addr[1:addr.index(']')]
    return addr


def parse_snort_alert(line, now=None):
    try:
        data = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    ts = _snort_time(data.get('timestamp', ''), now) or int(now or time.time())
    src = _strip_port(data.get('src_ap') or data.get('src_addr') or '')
    dst = _strip_port(data.get('dst_ap') or data.get('dst_addr') or '')
    device, remote = split_parties(src, dst)
    try:
        priority = int(data.get('priority', 3))
    except (TypeError, ValueError):
        priority = 3
    severity = {1: 'critical', 2: 'high', 3: 'medium'}.get(priority, 'low')
    action = 'blocked' if str(data.get('action', '')).lower() in ('block', 'drop', 'reject', 'blocked') else 'detected'
    return {'ts': ts, 'layer': 'ips', 'action': action, 'severity': severity, 'client': device, 'remote': remote,
            'reason': data.get('msg') or data.get('rule') or 'IPS alert', 'detail': data.get('class') or ''}


def parse_av_detection(entry):
    if not isinstance(entry, dict) or not entry.get('time'):
        return None
    reason = str(entry.get('reason') or 'antivirus')
    if reason == 'engine-down':
        return None  # a service problem, not a threat
    return {'ts': int(entry['time']), 'layer': 'antivirus', 'action': 'blocked', 'severity': 'high',
            'client': str(entry.get('client') or ''), 'remote': '', 'reason': reason, 'detail': str(entry.get('detail') or '')}


def parse_squid_line(line):
    """A request Squid refused (policy of Web Protection). Internal requests of the firewall itself are ignored."""
    parts = line.split()
    if len(parts) < 7 or 'DENIED' not in parts[3] or 'squid-internal' in line:
        return None
    try:
        ts = int(float(parts[0]))
    except ValueError:
        return None
    url = parts[6]
    host = re.sub(r'^[a-z]+://', '', url).split('/')[0].split(':')[0]
    return {'ts': ts, 'layer': 'web', 'action': 'blocked', 'severity': 'low', 'client': parts[2], 'remote': host,
            'reason': 'web policy', 'detail': url[:200]}


# ---------------------------------------------------------------- store

def connect(path=None):
    path = path or DB_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    db = sqlite3.connect(path, timeout=10)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute(
        'CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, layer TEXT NOT NULL, '
        'action TEXT NOT NULL, severity TEXT NOT NULL, client TEXT, remote TEXT, reason TEXT, detail TEXT, count INTEGER DEFAULT 1)'
    )
    db.execute('CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)')
    db.execute('CREATE TABLE IF NOT EXISTS cursor (source TEXT PRIMARY KEY, value TEXT)')
    return db


def add_events(db, events):
    """Insert events; the same device/remote/reason in the same minute and layer is one row with a count."""
    added = 0
    for ev in events:
        minute = ev['ts'] - ev['ts'] % 60
        row = db.execute(
            'SELECT id FROM events WHERE ts=? AND layer=? AND action=? AND client=? AND remote=? AND reason=?',
            (minute, ev['layer'], ev['action'], ev.get('client', ''), ev.get('remote', ''), ev.get('reason', '')),
        ).fetchone()
        if row:
            db.execute('UPDATE events SET count=count+1 WHERE id=?', (row[0],))
        else:
            db.execute(
                'INSERT INTO events (ts, layer, action, severity, client, remote, reason, detail) VALUES (?,?,?,?,?,?,?,?)',
                (minute, ev['layer'], ev['action'], ev['severity'], ev.get('client', ''), ev.get('remote', ''),
                 ev.get('reason', ''), ev.get('detail', '')),
            )
        added += 1
    return added


def prune(db, now=None):
    cutoff = int((now or time.time()) - RETENTION_DAYS * 86400)
    db.execute('DELETE FROM events WHERE ts < ?', (cutoff,))


def _get_cursor(db, source):
    row = db.execute('SELECT value FROM cursor WHERE source=?', (source,)).fetchone()
    return json.loads(row[0]) if row else None


def _set_cursor(db, source, value):
    db.execute('INSERT OR REPLACE INTO cursor (source, value) VALUES (?,?)', (source, json.dumps(value)))


def read_new_lines(db, source, path):
    """New complete lines of a growing text file. The cursor keeps inode and offset; a rotated or truncated file is read
    from the start. The first run starts at the end of the file's last 8 MiB so a huge old log is not replayed."""
    try:
        st = os.stat(path)
    except OSError:
        return []
    cur = _get_cursor(db, source) or {}
    offset = cur.get('offset')
    if offset is None or cur.get('inode') != st.st_ino or offset > st.st_size:
        offset = max(0, st.st_size - MAX_READ_BYTES) if offset is None else 0
    with open(path, 'rb') as fh:
        fh.seek(offset)
        data = fh.read(MAX_READ_BYTES)
    end = data.rfind(b'\n')
    if end < 0:
        _set_cursor(db, source, {'inode': st.st_ino, 'offset': offset})
        return []
    chunk = data[:end + 1]
    _set_cursor(db, source, {'inode': st.st_ino, 'offset': offset + len(chunk)})
    return chunk.decode('utf-8', errors='replace').splitlines()


def collect(db=None, now=None):
    """Read what is new in every source into the store. Returns the number of events added per source."""
    own = db is None
    db = db or connect()
    result = {}
    try:
        events = []
        for line in read_new_lines(db, 'syslog', SYSLOG):
            if 'banIP' in line or 'NXDOMAIN' in line:
                ev = parse_syslog_line(line, now)
                if ev:
                    events.append(ev)
        result['syslog'] = add_events(db, events)

        events = []
        try:
            names = sorted(f for f in os.listdir(SNORT_DIR) if f.endswith('_alert_json.txt'))
        except OSError:
            names = []
        for name in names:
            for line in read_new_lines(db, 'snort:' + name, os.path.join(SNORT_DIR, name)):
                ev = parse_snort_alert(line, now)
                if ev:
                    events.append(ev)
        result['snort'] = add_events(db, events)

        events = []
        last = (_get_cursor(db, 'av') or {}).get('time', 0)
        newest = last
        try:
            with open(AV_DETECTIONS) as fh:
                items = json.load(fh)
        except (OSError, ValueError):
            items = []
        for entry in items if isinstance(items, list) else []:
            ev = parse_av_detection(entry)
            if ev and ev['ts'] > last:
                events.append(ev)
                newest = max(newest, ev['ts'])
        result['antivirus'] = add_events(db, events)
        _set_cursor(db, 'av', {'time': newest})

        events = []
        for line in read_new_lines(db, 'squid', SQUID_LOG):
            if 'DENIED' in line:
                ev = parse_squid_line(line)
                if ev:
                    events.append(ev)
        result['web'] = add_events(db, events)

        prune(db, now)
        db.commit()
    finally:
        if own:
            db.close()
    return result


# ---------------------------------------------------------------- queries

def _range(days, now=None):
    now = int(now or time.time())
    if days <= 1:
        start = int(datetime.fromtimestamp(now).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    else:
        start = now - days * 86400
    return start, now


def _top(rows, key, limit):
    counts = defaultdict(int)
    for row in rows:
        if row[key]:
            counts[row[key]] += row['count']
    return [{'id': k, 'count': v} for k, v in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]]


def risk_list(rows, limit=10):
    """Devices ordered by risk: weight of the layer times the severity factor times the number of events."""
    score = defaultdict(int)
    layers = defaultdict(lambda: defaultdict(int))
    worst = {}
    for row in rows:
        device = row['client']
        if not device or not is_internal(device):
            continue
        score[device] += RISK_WEIGHTS.get(row['layer'], 1) * SEVERITY_FACTOR.get(row['severity'], 1) * row['count']
        layers[device][row['layer']] += row['count']
        if SEVERITIES.index(row['severity']) >= SEVERITIES.index(worst.get(device, 'low')):
            worst[device] = row['severity']
    ordered = sorted(score.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [{'device': d, 'score': s, 'severity': worst.get(d, 'low'), 'layers': dict(layers[d])} for d, s in ordered]


def summary(db, days=1, now=None, limit=10):
    """Counters, timeline, top lists and the risk list of the last ``days`` days (1 = today), with the previous period for comparison."""
    start, end = _range(days, now)
    span = max(end - start, 1)
    db.row_factory = sqlite3.Row
    rows = db.execute('SELECT * FROM events WHERE ts >= ? AND ts <= ?', (start, end)).fetchall()
    # today is compared with yesterday up to the same time of day; longer ranges with the period of the same length before
    p_start, p_end = (start - 86400, end - 86400) if days <= 1 else (start - span, start)
    prev = db.execute('SELECT COALESCE(SUM(count),0) FROM events WHERE ts >= ? AND ts < ?', (p_start, p_end)).fetchone()[0]
    by_layer = defaultdict(int)
    by_action = defaultdict(int)
    for row in rows:
        by_layer[row['layer']] += row['count']
        by_action[row['action']] += row['count']
    bucket = 3600 if days <= 1 else 86400
    timeline = defaultdict(lambda: defaultdict(int))
    for row in rows:
        timeline[row['ts'] - row['ts'] % bucket][row['layer']] += row['count']
    total = sum(by_layer.values())
    return {
        'range': {'start': start, 'end': end, 'days': days, 'bucket': bucket},
        'total': total,
        'previous_total': prev,
        'by_layer': {layer: by_layer.get(layer, 0) for layer in LAYERS},
        'by_action': dict(by_action),
        'timeline': [{'ts': ts, 'layers': dict(v)} for ts, v in sorted(timeline.items())],
        'top_devices': _top(rows, 'client', limit),
        'top_sources': _top(rows, 'remote', limit),
        'top_reasons': _top(rows, 'reason', limit),
        'at_risk': risk_list(rows, limit),
        'weights': RISK_WEIGHTS,
        'retention_days': RETENTION_DAYS,
    }


def events(db, days=1, layer=None, search=None, limit=100, offset=0, now=None):
    start, end = _range(days, now)
    db.row_factory = sqlite3.Row
    sql = 'SELECT * FROM events WHERE ts >= ? AND ts <= ?'
    args = [start, end]
    if layer:
        sql += ' AND layer = ?'
        args.append(layer)
    if search:
        sql += ' AND (client LIKE ? OR remote LIKE ? OR reason LIKE ? OR detail LIKE ?)'
        args += ['%' + search + '%'] * 4
    total = db.execute(sql.replace('SELECT *', 'SELECT COUNT(*)', 1), args).fetchone()[0]
    sql += ' ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?'
    args += [max(1, min(int(limit), 500)), max(0, int(offset))]
    return {'total': total, 'events': [dict(r) for r in db.execute(sql, args).fetchall()]}
