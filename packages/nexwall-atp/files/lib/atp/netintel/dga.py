# Copyright (C) 2026 Nexwall
"""Domains made by an algorithm (DGA) look different from names people choose: longer random runs, no words, few vowels, an unusual
mix of digits. `features` turns the registered name into numbers; `score` is a logistic model on them. The weights below are a
starting point fitted by hand on synthetic names: `train` fits them on a labelled list (benign top lists vs. known DGA families)
and `save`/`load` keep them as signed JSON like the other catalogs. Nothing here is a verdict: a high score is evidence for the
review queue and for the Collective Defense candidates, never a block on its own (docs/ATP-PLAN.md, capability 3)."""
import json
import math
import random

VOWELS = set('aeiouáéíóúãõâêô')
SECOND_LEVEL = {'com', 'net', 'org', 'gov', 'edu', 'co', 'ac', 'or', 'ne', 'gob', 'mil'}
FEATURES = ('length', 'entropy', 'digit_ratio', 'vowel_ratio', 'max_consonant_run', 'hyphens', 'unique_ratio', 'bigram_rare')
# the most common letter pairs of English, Portuguese and Spanish names: pairs outside this set count as rare
COMMON_BIGRAMS = set('''th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea
ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai sh ir su id os iv ia am fi ci
da do ue qu em ra nh lh rr ão pa sa tu vi ba ga fa ju mu ve pu ca co'''.split())


def registered_name(domain):
    """'cdn.shop.example.com.br' -> 'example'; the label that someone chose (or an algorithm made)."""
    parts = [p for p in domain.lower().strip('.').split('.') if p]
    if len(parts) < 2:
        return parts[0] if parts else ''
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return parts[-3]
    return parts[-2]


def features(domain):
    n = registered_name(domain)
    if not n:
        return {k: 0.0 for k in FEATURES}
    counts = {}
    for c in n:
        counts[c] = counts.get(c, 0) + 1
    ent = -sum(v / len(n) * math.log2(v / len(n)) for v in counts.values())
    run = best = 0
    for c in n:
        if c.isalpha() and c not in VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    pairs = [n[i:i + 2] for i in range(len(n) - 1) if n[i:i + 2].isalpha()]
    rare = sum(1 for p in pairs if p not in COMMON_BIGRAMS) / len(pairs) if pairs else 0.0
    letters = [c for c in n if c.isalpha()]
    return {
        'length': float(len(n)), 'entropy': ent, 'digit_ratio': sum(c.isdigit() for c in n) / len(n),
        'vowel_ratio': (sum(c in VOWELS for c in letters) / len(letters)) if letters else 0.0,
        'max_consonant_run': float(best), 'hyphens': float(n.count('-')),
        'unique_ratio': len(counts) / len(n), 'bigram_rare': rare,
    }


# hand-fitted starting weights (synthetic names); replaced by `train` on the real corpora
WEIGHTS = {'bias': -9.0, 'length': 0.12, 'entropy': 0.9, 'digit_ratio': 2.5, 'vowel_ratio': -2.0, 'max_consonant_run': 0.45,
           'hyphens': -0.5, 'unique_ratio': 0.0, 'bigram_rare': 4.0}


def score(domain, weights=None):
    w = weights or WEIGHTS
    f = features(domain)
    z = w['bias'] + sum(w.get(k, 0.0) * v for k, v in f.items())
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


def train(domains, labels, epochs=200, rate=0.05, seed=7):
    """Logistic regression by stochastic gradient descent (labels: 1 = DGA, 0 = chosen). Returns a weights dict."""
    rng = random.Random(seed)
    w = {k: 0.0 for k in ('bias',) + FEATURES}
    rows = [(features(d), y) for d, y in zip(domains, labels)]
    scale = {k: max(1e-9, max(abs(r[0][k]) for r in rows)) for k in FEATURES}
    for _ in range(epochs):
        rng.shuffle(rows)
        for f, y in rows:
            z = w['bias'] + sum(w[k] * f[k] / scale[k] for k in FEATURES)
            p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
            g = p - y
            w['bias'] -= rate * g
            for k in FEATURES:
                w[k] -= rate * g * f[k] / scale[k]
    # fold the scaling into the weights so score() can use raw features
    out = {'bias': w['bias']}
    for k in FEATURES:
        out[k] = w[k] / scale[k]
    return out


def save(weights, path):
    with open(path, 'w') as fp:
        json.dump(weights, fp, indent=1, sort_keys=True)


def load(path):
    with open(path) as fp:
        return json.load(fp)
