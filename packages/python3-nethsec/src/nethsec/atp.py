#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Advanced Threat Protection and Collective Protection on the firewall: what the web interface needs to know about them.

* ``assess_scorer`` turns the status file of the scorer service (``/usr/sbin/nexwall-atp status``) into one state:
  ``running``, ``degraded`` (it works but something is wrong, with the reasons), ``stopped`` (switched on, not running),
  ``off``, ``not_in_plan``.
* ``assess_collective`` does the same for Collective Protection (the shared lists and the shared reports).
* ``metrics`` reads the live figures of the scorer process (CPU, memory) and of the system, like the engine monitors of the
  other protections, plus the counters the scorer keeps.

Pure functions where possible (unit tested); ``collect`` and ``status`` read /proc and run the status command.
"""

import json
import os
import subprocess
import time

from nethsec import engine_metrics as em

STATUS_CMD = '/usr/sbin/nexwall-atp'
FEED_CMD = '/usr/sbin/nexwall-threat-feeds'
ATP_CATEGORIES = ('atp_ip', 'atp_dns')
# the scorer writes its status once per cycle (60 s by default); a file older than this many cycles means it stopped
STALE_CYCLES = 5
ERROR_WINDOW = 600  # an error older than this is history, not a problem now
UPDATE_HOURS = (1, 3, 6, 12, 24)


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def assess_scorer(status, now=None):
    """-> {'state': ..., 'reasons': [...]}. ``status`` is the JSON of ``nexwall-atp status`` (with 'alive' and 'age' added by it)."""
    now = now if now is not None else time.time()
    st = status if isinstance(status, dict) else {}
    reasons = []
    if st.get('entitled') is False:
        return {'state': 'not_in_plan', 'reasons': []}
    if not st.get('enabled', False):
        return {'state': 'off', 'reasons': []}
    interval = _int(st.get('interval')) or 60
    age = st.get('age')
    if not st.get('alive') or age is None or age > STALE_CYCLES * interval or st.get('state') in (None, 'not_running'):
        return {'state': 'stopped', 'reasons': ['service_not_running']}
    if st.get('state') == 'no_model':
        reasons.append('no_model')
    elif st.get('state') == 'not_licensed':
        return {'state': 'not_in_plan', 'reasons': []}
    if not st.get('dns_view'):
        reasons.append('no_dns_view')
    err_ts = _int(st.get('last_error_ts'))
    if st.get('last_error') and err_ts and now - err_ts <= ERROR_WINDOW:
        reasons.append('recent_error')
    if st.get('model_stale'):
        reasons.append('model_stale')
    return {'state': 'degraded' if reasons else 'running', 'reasons': reasons}


def assess_collective(settings, feeds, status, modules=None, services=None):
    """Collective Protection = the shared lists (atp_ip, atp_dns of the threat feed bundle) and, when sharing is on, the reports.
    ``feeds`` is the JSON of ``nexwall-threat-feeds status --json``; ``status`` the scorer status (for the report state);
    ``services`` says whether the services that apply the lists are switched on: {'ip': IP & Geo Blocking (banIP), 'dns': DNS Filtering (adblock)},
    True / False, or None when unknown. A shared list in a service that is off is not applied."""
    s = settings if isinstance(settings, dict) else {}
    f = feeds if isinstance(feeds, dict) else {}
    if modules is not None and not modules.get('atp', True):
        return {'state': 'not_in_plan', 'reasons': []}
    if f.get('license_state') in ('unlicensed',):
        return {'state': 'not_in_plan', 'reasons': []}
    if not s.get('collective', True):
        return {'state': 'off', 'reasons': []}
    svc = services if isinstance(services, dict) else {}
    cats = {c.get('id'): c for c in (f.get('categories') or []) if isinstance(c, dict) and c.get('id') in ATP_CATEGORIES}
    reasons = []
    if not f.get('version'):
        reasons.append('no_bundle')
    elif not cats:
        reasons.append('no_categories')
    else:
        for cid, c in cats.items():
            if not c.get('enabled'):
                reasons.append('list_off:' + cid)
            elif not c.get('downloaded'):
                reasons.append('list_missing:' + cid)
            elif svc.get({'atp_ip': 'ip', 'atp_dns': 'dns'}.get(cid)) is False:
                reasons.append('service_off:' + {'atp_ip': 'ip', 'atp_dns': 'dns'}[cid])
    if f.get('last_error'):
        reasons.append('update_error')
    if s.get('share', True) and isinstance(status, dict) and status.get('entitled') is not False:
        rep = status.get('report') or {}
        if rep.get('last_error'):
            reasons.append('report_error')
    return {'state': 'degraded' if reasons else 'running', 'reasons': reasons}


def lists_summary(feeds):
    """What the shared lists hold on this unit: per list enabled/downloaded/entries, and the bundle they came with."""
    f = feeds if isinstance(feeds, dict) else {}
    out = {'version': f.get('version'), 'last_check': f.get('last_check'), 'last_result': f.get('last_result'), 'last_error': f.get('last_error'), 'lists': {}}
    for c in f.get('categories') or []:
        if isinstance(c, dict) and c.get('id') in ATP_CATEGORIES:
            out['lists'][c['id']] = {'enabled': bool(c.get('enabled')), 'downloaded': bool(c.get('downloaded')), 'entries': _int(c.get('count')) or 0}
    return out


def derive_status(raw):
    """The scorer status file plus what only the reader can tell: is the process there, how old is the file."""
    st = dict(raw) if isinstance(raw, dict) else {}
    ts = _int(st.get('ts'))
    pid = _int(st.get('pid'))
    st['alive'] = bool(pid and os.path.exists('/proc/%d' % pid))
    st['age'] = max(0, int(time.time()) - ts) if ts else None
    return st


def collect(status, proc=em.PROC, sample=em.SAMPLE_SECONDS, clock_ticks=None):
    """Live figures: system CPU and memory, CPU and memory of the scorer process (by the pid it wrote), connections of the scorer's own view."""
    hz = clock_ticks or os.sysconf('SC_CLK_TCK')
    pid = _int((status or {}).get('pid'))
    if pid and not os.path.exists(os.path.join(proc, str(pid))):
        pid = None
    busy0, total0 = em.cpu_ticks(em._read(os.path.join(proc, 'stat')))
    p0 = em.process_cpu_ticks(pid, proc) if pid else 0
    t0 = time.monotonic()
    time.sleep(sample)
    elapsed = max(time.monotonic() - t0, 0.001)
    busy1, total1 = em.cpu_ticks(em._read(os.path.join(proc, 'stat')))
    cores = max(1, sum(1 for line in em._read(os.path.join(proc, 'stat')).splitlines() if line.startswith('cpu') and line[3:4].isdigit()))
    system_cpu = round(100.0 * (busy1 - busy0) / (total1 - total0), 1) if total1 > total0 else 0.0
    mem = em.memory(em._read(os.path.join(proc, 'meminfo')))
    mem['used_pct'] = round(100.0 * mem['used_kib'] / mem['total_kib'], 1) if mem['total_kib'] else 0.0
    if pid:
        rss, threads = em.process_memory(pid, proc)
        used = em.process_cpu_ticks(pid, proc) - p0
        engine = {'running': True, 'cpu_pct': round(100.0 * max(0, used) / hz / elapsed, 1), 'rss_kib': rss, 'threads': threads}
    else:
        engine = {'running': False, 'cpu_pct': 0.0, 'rss_kib': 0, 'threads': 0}
    st = status or {}
    return {
        'time': int(time.time()),
        'cpu': {'system_pct': system_cpu, 'cores': cores},
        'memory': mem,
        'engines': {'atp': engine},
        'counters': {k: st.get(k, 0) for k in ('cycles', 'flows_read', 'dns_records', 'events_total')},
        'scorer': {'hosts': st.get('hosts', 0), 'last_cycle_ms': st.get('last_cycle_ms', 0), 'interval': st.get('interval', 60),
                   'dns_view': st.get('dns_view', []), 'model': st.get('model'), 'model_version': st.get('model_version')},
    }


def _run_json(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return json.loads(p.stdout) if p.stdout.strip() else {}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}


def read_status():
    return derive_status(_run_json([STATUS_CMD, 'status']))


def services_from_uci(get):
    """{'ip': bool|None, 'dns': bool|None} from the switches of the services that apply the lists: banIP (IP & Geo Blocking) and adblock
    (DNS Filtering). `get(key)` returns the UCI value or ''. Read from the configuration, not from the services' status commands: those are
    slow and the page is polled."""
    def flag(key):
        v = get(key)
        return True if v == '1' else False if v in ('0', '') else None
    return {'ip': flag('banip.global.ban_enabled'), 'dns': flag('adblock.global.adb_enabled')}


def read_services():
    def get(key):
        try:
            return subprocess.run(['uci', '-q', 'get', key], capture_output=True, text=True, timeout=5).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return 'x'          # unreadable: not 0, not 1, not empty: the services are reported as unknown
    return services_from_uci(get)


def read_feeds():
    return _run_json([FEED_CMD, 'status', '--json'])


def start_update():
    """Look for a new model and new lists now, and send the report: in the background (the lists can take a while). -> {'message': ...}"""
    started = []
    for cmd in ([STATUS_CMD, 'update', '--force'], [STATUS_CMD, 'report', '--force'], [FEED_CMD, 'update', '--force']):
        if updating(cmd[0], cmd[1]):
            continue
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        started.append(cmd[1])
    return {'message': 'started' if started else 'running', 'started': started}


def updating(path, sub, proc=em.PROC):
    """Is `path sub ...` running now? (looks at the command lines)."""
    me = os.getpid()
    try:
        entries = os.listdir(proc)
    except OSError:
        return False
    for e in entries:
        if not e.isdigit() or int(e) == me:
            continue
        cmdline = em._read(os.path.join(proc, e, 'cmdline')).split('\0')
        if len(cmdline) >= 3 and cmdline[1] == path and cmdline[2] == sub:
            return True
    return False
