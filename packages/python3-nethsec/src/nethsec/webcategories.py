#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Traffic by web category for the dashboard, Traffic Analytics and the executive report.

The daily traffic reports hold bytes per website for every device. The category of a website comes from the domain lists
Web Protection has installed for the traffic engine (``categories.d``, one list per category). Those lists are big (millions of
domains), so they are never loaded whole: the websites of the days asked for are looked up in one streaming pass, and the
answer for each website is remembered next to the threat events. A website that is in no installed list is "uncategorized";
the result says how many lists were used so the page can tell the administrator when coverage is partial.
"""

import ipaddress
import json
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta

REPORT_DIR = '/mnt/data/dpireport'
CATEGORIES_D = '/etc/netifyd/categories.d'
CACHE_DIR = '/mnt/data/threats'
HOST_CACHE = 'webcat-hosts.json'
LIST_PREFIX = '50-ut1-'
UNCATEGORIZED = 'uncategorized'
# When a website is in several lists the first one here wins (security categories first); unlisted ones follow alphabetically.
PRIORITY = ['malware', 'phishing', 'cryptojacking', 'stalkerware', 'ddos', 'hacking', 'dangerous-material', 'adult',
            'mixed-adult', 'gambling', 'warez', 'dialer', 'vpn', 'residential-proxies', 'redirector', 'remote-control']


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def suffixes(host):
    """The website and its parent domains, longest first ('a.b.example.com' -> a.b.example.com, b.example.com, example.com)."""
    parts = host.lower().strip('.').split('.')
    return ['.'.join(parts[i:]) for i in range(max(len(parts) - 1, 1))]


def category_lists(directory=None):
    """(category, path) of the installed domain lists, in priority order."""
    directory = directory or CATEGORIES_D
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return []
    found = {}
    for name in names:
        if name.startswith(LIST_PREFIX) and name.endswith('.conf'):
            found[name[len(LIST_PREFIX):-5]] = os.path.join(directory, name)
    ordered = [c for c in PRIORITY if c in found] + sorted(c for c in found if c not in PRIORITY)
    return [(c, found[c]) for c in ordered]


def lookup(hosts, lists):
    """Category of each website: one streaming pass over the lists, only the wanted names are kept."""
    wanted = {}
    for host in hosts:
        if _is_ip(host) or '.' not in host:
            continue
        for s in suffixes(host):
            wanted.setdefault(s, set()).add(host)
    result = {}
    if not wanted:
        return result
    for category, path in lists:
        try:
            with open(path, encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    if not line.startswith('dom:'):
                        continue
                    domain = line[4:].strip().lower()
                    targets = wanted.get(domain)
                    if targets:
                        for host in targets:
                            result.setdefault(host, category)
        except OSError:
            continue
    return result


def signature(lists):
    """Changes whenever an installed list changes, so remembered answers are dropped then."""
    parts = []
    for category, path in lists:
        try:
            st = os.stat(path)
            parts.append('%s:%d:%d' % (category, st.st_size, int(st.st_mtime)))
        except OSError:
            continue
    return '|'.join(parts)


def _load_cache(cache_dir):
    try:
        with open(os.path.join(cache_dir, HOST_CACHE)) as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {}


def _save_cache(cache_dir, data):
    os.makedirs(cache_dir, exist_ok=True)
    path = os.path.join(cache_dir, HOST_CACHE)
    with open(path + '.new', 'w') as fh:
        json.dump(data, fh)
    os.replace(path + '.new', path)


def host_categories(hosts, lists=None, cache_dir=None):
    """Category of each website ('uncategorized' when no installed list has it), remembered between calls."""
    lists = category_lists() if lists is None else lists
    cache_dir = cache_dir or CACHE_DIR
    sig = signature(lists)
    cache = _load_cache(cache_dir)
    if cache.get('signature') != sig:
        cache = {'signature': sig, 'hosts': {}}
    known = cache.setdefault('hosts', {})
    unknown = [h for h in hosts if h not in known]
    if unknown:
        found = lookup(unknown, lists)
        for host in unknown:
            known[host] = found.get(host, UNCATEGORIZED)
        if len(known) > 200000:  # keep the file small: drop the oldest half
            for key in list(known)[:100000]:
                del known[key]
        try:
            _save_cache(cache_dir, cache)
        except OSError:
            pass
    return {h: known[h] for h in hosts if h in known}


def day_hosts(day, report_dir=None):
    """Bytes per website of one day, summed over the devices and hours of the traffic report."""
    base = os.path.join(report_dir or REPORT_DIR, '%04d' % day.year, '%02d' % day.month, '%02d' % day.day)
    totals = defaultdict(int)
    try:
        clients = os.listdir(base)
    except OSError:
        return totals
    for client in clients:
        folder = os.path.join(base, client)
        try:
            files = os.listdir(folder)
        except OSError:
            continue
        for name in files:
            if not name.endswith('.json'):
                continue
            try:
                with open(os.path.join(folder, name)) as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                continue
            for host, count in (data.get('host') or {}).items():
                if isinstance(count, (int, float)):
                    totals[host] += count
    return totals


def web_categories(days=1, now=None, report_dir=None, cache_dir=None, directory=None, limit=12):
    """Traffic by category of the last ``days`` days (1 = today)."""
    now = now or time.time()
    today = datetime.fromtimestamp(now).date()
    lists = category_lists(directory)
    hosts = defaultdict(int)
    for i in range(max(1, days)):
        for host, count in day_hosts(today - timedelta(days=i), report_dir).items():
            hosts[host] += count
    by_host = host_categories(list(hosts), lists, cache_dir)
    totals = defaultdict(int)
    for host, count in hosts.items():
        totals[by_host.get(host, UNCATEGORIZED)] += count
    all_bytes = sum(totals.values())
    categorized = all_bytes - totals.get(UNCATEGORIZED, 0)
    ranked = sorted(((c, n) for c, n in totals.items() if c != UNCATEGORIZED), key=lambda kv: kv[1], reverse=True)
    return {
        'days': days,
        'total': all_bytes,
        'categorized': categorized,
        'uncategorized': totals.get(UNCATEGORIZED, 0),
        'lists_installed': len(lists),
        'categories': [{'id': c, 'traffic': n} for c, n in ranked[:limit]],
    }
