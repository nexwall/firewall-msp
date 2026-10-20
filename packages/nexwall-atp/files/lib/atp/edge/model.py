# Copyright (C) 2026 Nexwall
"""The model file the ATP VM publishes and the firewall scores against: a small JSON document (logistic regression over named features),
signed with a detached signature that the firewall checks with OpenSSL before it uses the file. The file says how its features have to be
computed (window, history, beacon figures) so that the firewall never guesses.

{"format": 1, "name": "...", "version": "2026.10.15.1", "trained": "2026-10-15", "trained_on": "text",
 "window": 900, "history_windows": 2, "beacon_min_events": 4, "beacon_full_events": 15,
 "features": [...], "mean": [...], "std": [...], "coef": [...], "intercept": 0.0,
 "thresholds": {"review": 0.9, "high": 0.99}, "limits": "text"}"""
import hashlib
import json
import math
import subprocess

FORMAT = 1
# Heavy-tailed counts and volumes; a model with "transform": "log" applies log1p to these before standardising (same list as netintel.flowfeatures.LOG_FEATURES).
LOG_FEATURES = ('beacon_count', 'bytes_down', 'bytes_up', 'destinations', 'dns_dga_high', 'dns_queries', 'dns_unique', 'flows', 'long_quiet',
                'new_domain_flows', 'rare_destinations', 'uncommon_port_flows')
TRANSFORMS = (None, 'none', 'log')

REQUIRED = ('format', 'name', 'version', 'window', 'history_windows', 'beacon_min_events', 'beacon_full_events', 'features', 'mean', 'std', 'coef', 'intercept', 'thresholds')


class ModelError(Exception):
    pass


def validate(m):
    for k in REQUIRED:
        if k not in m:
            raise ModelError('missing field %s' % k)
    if m['format'] != FORMAT:
        raise ModelError('unsupported format %s' % m['format'])
    n = len(m['features'])
    if not (len(m['mean']) == len(m['std']) == len(m['coef']) == n) or n == 0:
        raise ModelError('features, mean, std and coef must have the same length')
    if m.get('transform') not in TRANSFORMS:
        raise ModelError('unsupported transform %s' % m.get('transform'))
    if any(s <= 0 for s in m['std']):
        raise ModelError('std must be positive')
    if not (0 < m['thresholds'].get('review', 0) <= m['thresholds'].get('high', 1) <= 1):
        raise ModelError('thresholds must satisfy 0 < review <= high <= 1')
    return m


def load(path):
    with open(path, 'rb') as fp:
        raw = fp.read()
    try:
        m = json.loads(raw.decode('utf8'))
    except ValueError as e:
        raise ModelError('not JSON: %s' % e)
    m = validate(m)
    m['_sha256'] = hashlib.sha256(raw).hexdigest()
    return m


def verify_signature(path, sig_path, pubkey_path, run=subprocess.run):
    """True when `sig_path` is a valid signature of `path` under the public key (OpenSSL, SHA-256). `run` is injectable for tests."""
    p = run(['openssl', 'dgst', '-sha256', '-verify', pubkey_path, '-signature', sig_path, path], capture_output=True, text=True)
    return p.returncode == 0 and 'Verified OK' in (p.stdout or '')


def sigmoid(z):
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def score(model, values):
    """values: dict feature -> number. Returns (probability, contributions) with contributions = [(feature, value, coef * standardised value)]."""
    z = model['intercept']
    contrib = []
    log = model.get('transform') == 'log'
    for name, mu, sd, c in zip(model['features'], model['mean'], model['std'], model['coef']):
        v = float(values.get(name, 0.0))
        if log and name in LOG_FEATURES:
            v = math.log1p(max(v, 0.0))
        t = c * (v - mu) / sd
        z += t
        contrib.append((name, v, t))
    return sigmoid(z), contrib
