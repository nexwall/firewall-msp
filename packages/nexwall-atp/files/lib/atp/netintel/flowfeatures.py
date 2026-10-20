# Copyright (C) 2026 Nexwall
"""Features of one host over a time window, from the flow records the firewall's DPI engine keeps and the DNS names the host asked.
The same function runs on the firewall (scoring) and on the ATP VM (training), so the model sees identical inputs in both places.

flow record (dict): {'local_ip', 'other_ip', 'other_port', 'ip_protocol', 'first_seen', 'last_seen', 'local_bytes', 'other_bytes',
                     'local_packets', 'other_packets', 'ja4' (optional), 'host_server_name' (optional)}
dns record (dict):  {'ts', 'name', 'rcode' ('NOERROR' | 'NXDOMAIN' | ...)}
Everything returned is a number. No payload and no full URL is ever read."""
import math
import os
import statistics

from atp.netintel import beacon, dga

# Experiment switch: 'all' (default) computes every destination-based feature over the history; 'beacon' only the beacon scores (ablation of Entry 16)
HISTORY_SCOPE = os.environ.get('ATP_HISTORY_SCOPE', 'all')
WELL_KNOWN_TLS_PORTS = (443, 8443)
COMMON_PORTS = {53, 80, 123, 143, 443, 465, 587, 853, 993, 995, 8080, 8443}


def _safe_ratio(a, b):
    return a / b if b else 0.0


def dns_features(queries, lm=None):
    names = [q['name'] for q in queries if q.get('name')]
    if not names:
        return {'dns_queries': 0.0, 'dns_unique': 0.0, 'dns_nxdomain_share': 0.0, 'dns_dga_max': 0.0, 'dns_dga_mean': 0.0, 'dns_dga_high': 0.0}
    scores = [dga.score(n) for n in set(names)]
    nx = sum(1 for q in queries if q.get('rcode') == 'NXDOMAIN')
    return {
        'dns_queries': float(len(names)), 'dns_unique': float(len(set(names))), 'dns_nxdomain_share': nx / len(queries),
        'dns_dga_max': max(scores), 'dns_dga_mean': sum(scores) / len(scores),
        # how many different names look generated: one odd name is noise, many is a pattern
        'dns_dga_high': float(sum(1 for s in scores if s > 0.8)),
    }


def destination_features(flows, min_events=8, full_events=60):
    """One row per destination (address and port) the host talked to; the host features are taken from the worst few."""
    by_dst = {}
    for f in flows:
        by_dst.setdefault((f['other_ip'], f['other_port']), []).append(f)
    rows = []
    for (ip, port), fl in by_dst.items():
        times = [f['first_seen'] for f in fl]
        b = beacon.analyse(times, min_events=min_events, full_events=full_events)
        up = sum(f.get('local_bytes', 0) for f in fl)
        down = sum(f.get('other_bytes', 0) for f in fl)
        durations = [max(0.0, f['last_seen'] - f['first_seen']) for f in fl]
        rows.append({'ip': ip, 'port': port, 'connections': len(fl), 'beacon_score': b['score'], 'beacon_period': b['period'],
                     'beacon_jitter': b['jitter'], 'up': up, 'down': down, 'ratio_up': _safe_ratio(up, up + down),
                     'long_quiet': float(max(durations) > 600 and (up + down) < 20000), 'uncommon_port': float(port not in COMMON_PORTS)})
    return rows


def host_features(flows, queries=(), window=600.0, rare_destinations=frozenset(), ja4_rare=frozenset(), history=None, beacon_min_events=8, beacon_full_events=60):
    """The feature vector of one host for one window. `rare_destinations` and `ja4_rare` come from the model file (what is rare across the fleet).
    `history`: optional longer list of the same host's flows (the window plus the windows before it): the destination and beacon features are then computed over it."""
    f = {'flows': float(len(flows)), 'window': float(window)}
    f.update(dns_features(list(queries)))
    # the beacon features may use a longer history of the same host (a beacon with a 2 minute period gives only 5 events in 10 minutes)
    rows = destination_features(flows if history is None else history, beacon_min_events, beacon_full_events)
    beacon_rows = rows
    if history is not None and HISTORY_SCOPE == 'beacon':
        rows = destination_features(flows, beacon_min_events, beacon_full_events)
        beacon_rows = rows if not history else destination_features(history, beacon_min_events, beacon_full_events)
    f['destinations'] = float(len(rows))
    scores = sorted((r['beacon_score'] for r in beacon_rows), reverse=True)
    f['beacon_max'] = scores[0] if scores else 0.0
    f['beacon_count'] = float(sum(1 for s in scores if s > 0.5))
    f['up_ratio_max'] = max((r['ratio_up'] for r in rows if r['up'] + r['down'] > 50000), default=0.0)
    f['bytes_up'] = float(sum(r['up'] for r in rows))
    f['bytes_down'] = float(sum(r['down'] for r in rows))
    f['long_quiet'] = float(sum(r['long_quiet'] for r in rows))
    f['uncommon_port_flows'] = float(sum(r['connections'] for r in rows if r['uncommon_port']))
    f['rare_destinations'] = float(sum(1 for r in rows if r['ip'] in rare_destinations))
    f['ja4_rare'] = float(sum(1 for fl in flows if fl.get('ja4') in ja4_rare))
    sizes = [(fl.get('local_bytes', 0) + fl.get('other_bytes', 0)) / max(fl.get('local_packets', 0) + fl.get('other_packets', 0), 1) for fl in flows]
    f['packet_size_spread'] = statistics.pstdev(sizes) if len(sizes) > 1 else 0.0
    f['new_domain_flows'] = float(sum(1 for fl in flows if fl.get('host_server_name') and fl['host_server_name'] not in {q['name'] for q in queries}))
    return f


FEATURE_NAMES = tuple(sorted(host_features([], []).keys()))


# Counts and volumes have heavy tails; ATP_TRANSFORM=log applies log1p to them before standardisation (default: unchanged).
LOG_FEATURES = ('beacon_count', 'bytes_down', 'bytes_up', 'destinations', 'dns_dga_high', 'dns_queries', 'dns_unique', 'flows', 'long_quiet',
                'new_domain_flows', 'rare_destinations', 'uncommon_port_flows')


def transform(X, names):
    """X (rows x names) -> the same matrix, log1p on the heavy-tailed columns when the environment variable ATP_TRANSFORM is "log"."""
    import os
    if os.environ.get('ATP_TRANSFORM', '') != 'log':
        return X
    return apply_log(X, names)


def apply_log(X, names):
    """log1p on the heavy-tailed columns of X (always)."""
    import numpy as np
    X = np.array(X, dtype=float, copy=True)
    for j, n in enumerate(names):
        if n in LOG_FEATURES:
            X[:, j] = np.log1p(np.maximum(X[:, j], 0.0))
    return X
