# Copyright (C) 2026 Nexwall
"""Flow scorer: keeps the recent flows and DNS names of every host in bounded memory, and every cycle scores the hosts against the model.
Advisory only: it returns events (a score, a level, the evidence in words); it never blocks anything. A CPU budget (hosts per cycle and seconds per
cycle) keeps it from ever competing with the firewall's work: what does not fit in a cycle waits for the next one."""
import time

from atp.capture import flowlog
from atp.edge import model as M
from atp.netintel import dga as dga_model
from atp.netintel import flowfeatures as ff

EVIDENCE = {
    'beacon_max': 'contacts a destination at regular intervals (regularity {v:.2f})',
    'beacon_count': 'regular check-ins to {v:.0f} destination(s)',
    'dns_dga_high': '{v:.0f} DNS name(s) with a generated look',
    'dns_dga_max': 'the most generated-looking DNS name scores {v:.2f}',
    'dns_nxdomain_share': '{v:.0%} of its DNS lookups fail',
    'dns_queries': '{v:.0f} DNS lookups in the window',
    'long_quiet': '{v:.0f} long, almost silent connection(s)',
    'up_ratio_max': 'sends far more than it receives (upload share {v:.0%})',
    'bytes_up': 'uploaded {v:.0f} bytes in the window',
    'uncommon_port_flows': '{v:.0f} connection(s) to uncommon ports',
    'destinations': 'talks to {v:.0f} different destinations',
    'flows': '{v:.0f} connections in the window',
}

MAX_INDICATORS = 5


class Scorer:
    def __init__(self, model, max_hosts=200, budget_seconds=2.0, min_flows=3, clock=time.monotonic):
        self.model = model
        self.max_hosts, self.budget, self.min_flows, self.clock = max_hosts, budget_seconds, min_flows, clock
        self.flows = {}      # host -> {digest: flow}
        self.dns = {}        # host -> [dns record]
        self.queue = []      # hosts waiting for a turn
        self.span = (model['history_windows'] + 1) * model['window']

    # ---- input
    def add_flows(self, records):
        for r in records:
            h = r.get('local_ip')
            if not h:
                continue
            d = self.flows.setdefault(h, {})
            k = r.get('digest') or (r.get('other_ip'), r.get('other_port'), r.get('first_seen'))
            d[k] = flowlog.merge(d.get(k), r)

    def add_dns(self, records):
        for r in records:
            if r.get('src_ip'):
                self.dns.setdefault(r['src_ip'], []).append(r)

    def prune(self, now):
        lo = now - self.span
        for h in list(self.flows):
            d = {k: f for k, f in self.flows[h].items() if f.get('last_seen', 0) >= lo}
            if d:
                self.flows[h] = d
            else:
                del self.flows[h]
        for h in list(self.dns):
            q = [r for r in self.dns[h] if r['ts'] >= lo]
            if q:
                self.dns[h] = q
            else:
                del self.dns[h]

    # ---- scoring
    def features(self, host, now):
        w = self.model['window']
        fl = list(self.flows.get(host, {}).values())
        cur = [f for f in fl if f['first_seen'] >= now - w]
        hist = [f for f in fl if f['first_seen'] >= now - self.span]
        q = [r for r in self.dns.get(host, []) if r['ts'] >= now - w]
        return len(cur), ff.host_features(cur, q, w, history=hist, beacon_min_events=self.model['beacon_min_events'], beacon_full_events=self.model['beacon_full_events'])

    def indicators(self, host, now):
        """The remote parties behind a flagged host's evidence: destinations it contacts at regular intervals and generated-looking names it asked.
        Only the remote side (an address or a name), never the internal host; the Collective Defense reports are made from these."""
        m = self.model
        hist = [f for f in self.flows.get(host, {}).values() if f['first_seen'] >= now - self.span]
        rows = ff.destination_features(hist, m['beacon_min_events'], m['beacon_full_events'])
        out = [{'type': 'ip', 'value': r['ip'], 'port': r['port'], 'beacon': round(r['beacon_score'], 2)}
               for r in sorted(rows, key=lambda r: -r['beacon_score']) if r['beacon_score'] > 0.5][:MAX_INDICATORS]
        names = {q['name'] for q in self.dns.get(host, []) if q['ts'] >= now - m['window'] and q.get('name')}
        scored = sorted(((dga_model.score(n), n) for n in names), reverse=True)
        out += [{'type': 'domain', 'value': n, 'dga': round(sc, 2)} for sc, n in scored if sc > 0.8][:MAX_INDICATORS]
        return out

    def score_host(self, host, now):
        n, feats = self.features(host, now)
        if n < self.min_flows:
            return None
        p, contrib = M.score(self.model, feats)
        th = self.model['thresholds']
        level = 'high' if p >= th['high'] else 'review' if p >= th['review'] else 'normal'
        top = sorted((c for c in contrib if c[2] > 0.5), key=lambda c: -c[2])[:4]
        evidence = [EVIDENCE.get(n_, n_ + ' = {v:.2f}').format(v=v) for n_, v, _ in top]
        return {'layer': 'atp', 'kind': 'flow-behaviour', 'host': host, 'score': round(p, 4), 'level': level, 'model': self.model['name'],
                'version': self.model['version'], 'window': self.model['window'], 'ts': now, 'evidence': evidence,
                'indicators': self.indicators(host, now) if level != 'normal' else []}

    def cycle(self, now):
        """One scoring cycle within the budget. Returns the events of hosts at 'review' or 'high' level."""
        self.prune(now)
        if not self.queue:
            self.queue = sorted(self.flows)
        start, events, done = self.clock(), [], 0
        while self.queue and done < self.max_hosts and self.clock() - start < self.budget:
            host = self.queue.pop(0)
            done += 1
            ev = self.score_host(host, now)
            if ev and ev['level'] != 'normal':
                events.append(ev)
        return events
