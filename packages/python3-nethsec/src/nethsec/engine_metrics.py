#!/usr/bin/python3

#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Live figures for the tuning windows of Application Control (DPI) and Network Protection (IPS): CPU and memory of the
whole system and of each engine, the packet queues of both engines (waiting and dropped packets) and the connection table.
Everything is read from /proc; CPU percentages are measured over a short interval inside the call.
"""

import os
import time

PROC = '/proc'
ENGINES = {'dpi': 'netifyd', 'ips': 'snort3'}
# packet queues: the DPI engine uses queue numbers from 50, the IPS the ones below (see ns-netifyd-configure, snort.nfq)
DPI_QUEUE_BASE = 50
SAMPLE_SECONDS = 0.5


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ''


def cpu_ticks(stat_text):
    """(busy, total) jiffies of the 'cpu' line of /proc/stat."""
    for line in stat_text.splitlines():
        if line.startswith('cpu '):
            values = [int(v) for v in line.split()[1:9]]
            total = sum(values)
            idle = values[3] + values[4]
            return total - idle, total
    return 0, 0


def process_ticks(stat_text):
    """utime + stime of a /proc/<pid>/stat, summed over its threads is read from the task directory by the caller."""
    # the command name may contain spaces and parentheses: fields start after the last ')'
    rest = stat_text[stat_text.rfind(')') + 2:].split()
    try:
        return int(rest[11]) + int(rest[12])
    except (IndexError, ValueError):
        return 0


def find_pid(name, proc=PROC):
    """Pid of the process whose command name is `name` (the main one: lowest pid), or None."""
    found = []
    try:
        entries = os.listdir(proc)
    except OSError:
        return None
    for entry in entries:
        if entry.isdigit() and _read(os.path.join(proc, entry, 'comm')).strip() == name:
            found.append(int(entry))
    return min(found) if found else None


def process_cpu_ticks(pid, proc=PROC):
    """Jiffies used by all threads of a process (the main thread's stat file only counts itself)."""
    total = 0
    task_dir = os.path.join(proc, str(pid), 'task')
    try:
        tids = os.listdir(task_dir)
    except OSError:
        return 0
    for tid in tids:
        total += process_ticks(_read(os.path.join(task_dir, tid, 'stat')))
    return total


def process_memory(pid, proc=PROC):
    """(resident KiB, threads) from /proc/<pid>/status."""
    rss, threads = 0, 0
    for line in _read(os.path.join(proc, str(pid), 'status')).splitlines():
        if line.startswith('VmRSS:'):
            rss = int(line.split()[1])
        elif line.startswith('Threads:'):
            threads = int(line.split()[1])
    return rss, threads


def memory(meminfo_text):
    """System memory in KiB: total, available, used (total - available)."""
    values = {}
    for line in meminfo_text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(':'):
            try:
                values[parts[0][:-1]] = int(parts[1])
            except ValueError:
                pass
    total = values.get('MemTotal', 0)
    available = values.get('MemAvailable', values.get('MemFree', 0))
    return {'total_kib': total, 'available_kib': available, 'used_kib': max(0, total - available)}


def queues(text):
    """
    Parse /proc/net/netfilter/nfnetlink_queue. Per engine: queues, packets waiting now, dropped because the queue was full
    (queue_dropped), dropped because the engine did not answer (user_dropped) and handled (the packet id counter, a
    wrapping 32-bit number: the caller uses differences).
    """
    out = {k: {'queues': 0, 'waiting': 0, 'dropped': 0, 'user_dropped': 0, 'handled': 0} for k in ENGINES}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            qid, waiting, dropped, user_dropped, seq = int(parts[0]), int(parts[2]), int(parts[5]), int(parts[6]), int(parts[7])
        except ValueError:
            continue
        engine = 'dpi' if qid >= DPI_QUEUE_BASE else 'ips'
        e = out[engine]
        e['queues'] += 1
        e['waiting'] += waiting
        e['dropped'] += dropped
        e['user_dropped'] += user_dropped
        e['handled'] += seq
    return out


def conntrack(proc=PROC):
    count = _read(os.path.join(proc, 'sys/net/netfilter/nf_conntrack_count')).strip()
    maximum = _read(os.path.join(proc, 'sys/net/netfilter/nf_conntrack_max')).strip()
    return {'count': int(count) if count.isdigit() else 0, 'max': int(maximum) if maximum.isdigit() else 0}


def collect(proc=PROC, sample=SAMPLE_SECONDS, clock_ticks=None):
    """One reading: measures CPU over `sample` seconds, everything else at the end of it."""
    hz = clock_ticks or os.sysconf('SC_CLK_TCK')
    pids = {k: find_pid(n, proc) for k, n in ENGINES.items()}
    busy0, total0 = cpu_ticks(_read(os.path.join(proc, 'stat')))
    p0 = {k: process_cpu_ticks(pid, proc) if pid else 0 for k, pid in pids.items()}
    t0 = time.monotonic()
    time.sleep(sample)
    elapsed = max(time.monotonic() - t0, 0.001)
    busy1, total1 = cpu_ticks(_read(os.path.join(proc, 'stat')))
    cores = max(1, sum(1 for line in _read(os.path.join(proc, 'stat')).splitlines() if line.startswith('cpu') and line[3:4].isdigit()))

    system_cpu = round(100.0 * (busy1 - busy0) / (total1 - total0), 1) if total1 > total0 else 0.0
    mem = memory(_read(os.path.join(proc, 'meminfo')))
    mem['used_pct'] = round(100.0 * mem['used_kib'] / mem['total_kib'], 1) if mem['total_kib'] else 0.0

    engines = {}
    for key, pid in pids.items():
        if not pid:
            engines[key] = {'running': False, 'cpu_pct': 0.0, 'rss_kib': 0, 'threads': 0}
            continue
        rss, threads = process_memory(pid, proc)
        used = process_cpu_ticks(pid, proc) - p0[key]
        # percent of ONE core (100 = one full core), the usual unit of top
        engines[key] = {'running': True, 'cpu_pct': round(100.0 * max(0, used) / hz / elapsed, 1), 'rss_kib': rss, 'threads': threads}
    return {
        'time': int(time.time()),
        'cpu': {'system_pct': system_cpu, 'cores': cores},
        'memory': mem,
        'engines': engines,
        'queues': queues(_read(os.path.join(proc, 'net/netfilter/nfnetlink_queue'))),
        'conntrack': conntrack(proc),
    }
