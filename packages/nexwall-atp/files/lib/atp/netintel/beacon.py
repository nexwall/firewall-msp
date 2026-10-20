# Copyright (C) 2026 Nexwall
"""Beaconing: malware that checks in with its server at regular intervals. From the times of the connections of one source to one
destination, `analyse` says how regular they are. Human traffic is bursty (a high spread of the gaps); a beacon has gaps close to
one period, with a small jitter. Needs no sandbox: it runs on the flow records the firewall already keeps, per source and destination
(and only with the customer's consent settings). Advisory, like every ATP signal."""
import math


def _median(values):
    s = sorted(values)
    n = len(s)
    return (s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0) if s else 0.0


def analyse(timestamps, min_events=8, tolerance=0.2, full_events=60):
    """-> dict(period, jitter, regular_ratio, score, events). `period` is the median gap in seconds, `regular_ratio` the share of
    gaps within `tolerance` of it, `jitter` the coefficient of variation of those gaps. score 0..1."""
    ts = sorted(float(t) for t in timestamps)
    if len(ts) < min_events:
        return {'period': 0.0, 'jitter': 0.0, 'regular_ratio': 0.0, 'score': 0.0, 'events': len(ts)}
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]
    if len(gaps) < min_events - 1:
        return {'period': 0.0, 'jitter': 0.0, 'regular_ratio': 0.0, 'score': 0.0, 'events': len(ts)}
    period = _median(gaps)
    if period < 1.0:
        # sub-second gaps are a transfer, not a check-in
        return {'period': period, 'jitter': 0.0, 'regular_ratio': 0.0, 'score': 0.0, 'events': len(ts)}
    near = [g for g in gaps if abs(g - period) <= tolerance * period]
    ratio = len(near) / len(gaps)
    mean = sum(near) / len(near) if near else period
    jitter = (math.sqrt(sum((g - mean) ** 2 for g in near) / len(near)) / mean) if near and mean else 1.0
    # more events and a tighter spread give more confidence; a run of 8 regular gaps is weak evidence, `full_events` (60 by default) is strong; a short window needs a lower figure
    volume = min(1.0, len(gaps) / float(full_events))
    score = ratio * (1.0 - min(1.0, jitter / tolerance)) * (0.4 + 0.6 * volume)
    return {'period': period, 'jitter': jitter, 'regular_ratio': ratio, 'score': max(0.0, min(1.0, score)), 'events': len(ts)}
