# Copyright (C) 2026 Nexwall
"""Capture of flow records for training: normalises the flow JSON of the firewall's DPI engine (as served by `ubus call ns.flows list`) into the
record of `atp.netintel.flowfeatures`, merges the several updates of one flow (same digest) into one record, and appends it to a JSON-lines file.
Runs on the firewall (a minute timer) and in tests. No payload is ever read: the DPI engine gives sizes, times, names and fingerprints."""
import json


def _ms_to_s(v):
    v = float(v or 0)
    return v / 1000.0 if v > 1e11 else v


def normalise(flow):
    """The `flow` object of an ns.flows entry -> a flow record (dict) or None when it lacks what the features need."""
    if not isinstance(flow, dict) or not flow.get('other_ip'):
        return None
    ssl = flow.get('ssl') or {}
    first = _ms_to_s(flow.get('first_seen_at') or flow.get('first_update_at'))
    last = _ms_to_s(flow.get('last_seen_at') or flow.get('last_update_at')) or first
    return {
        'digest': flow.get('digest', ''), 'local_ip': flow.get('local_ip', ''), 'other_ip': flow['other_ip'],
        'other_port': int(flow.get('other_port') or 0), 'ip_protocol': int(flow.get('ip_protocol') or 0),
        'first_seen': first, 'last_seen': max(first, last),
        'local_bytes': int(flow.get('local_bytes') or 0), 'other_bytes': int(flow.get('other_bytes') or 0),
        'local_packets': int(flow.get('local_packets') or 0), 'other_packets': int(flow.get('other_packets') or 0),
        'ja4': ssl.get('client_ja4') or '', 'host_server_name': flow.get('host_server_name') or ssl.get('client_sni') or '',
        'app': flow.get('detected_application_name') or '', 'protocol': flow.get('detected_protocol_name') or '',
    }


def merge(old, new):
    """Later update of the same flow: counters only grow, the last time moves forward, names appear when learned."""
    if old is None:
        return dict(new)
    m = dict(old)
    for k in ('local_bytes', 'other_bytes', 'local_packets', 'other_packets'):
        m[k] = max(old.get(k, 0), new.get(k, 0))
    m['last_seen'] = max(old.get('last_seen', 0), new.get('last_seen', 0))
    m['first_seen'] = min(x for x in (old.get('first_seen'), new.get('first_seen')) if x) if (old.get('first_seen') or new.get('first_seen')) else 0
    for k in ('ja4', 'host_server_name', 'app', 'protocol'):
        m[k] = old.get(k) or new.get(k) or ''
    return m


class FlowCollector:
    """Keeps the flows seen so far (by digest); `update(entries)` takes the list of an ns.flows answer; `drain(older_than)` returns the flows whose
    last update is older than `older_than` seconds (finished enough to be written) and forgets them."""

    def __init__(self):
        self.flows = {}
        self.updated = {}

    def update(self, entries, now):
        n = 0
        for e in entries:
            rec = normalise(e.get('flow') if isinstance(e, dict) and 'flow' in e else e)
            if not rec or not rec['digest']:
                continue
            self.flows[rec['digest']] = merge(self.flows.get(rec['digest']), rec)
            self.updated[rec['digest']] = now
            n += 1
        return n

    def drain(self, now, older_than=120.0):
        out = []
        for d in [d for d, t in self.updated.items() if now - t >= older_than]:
            out.append(self.flows.pop(d))
            del self.updated[d]
        return out


def write_jsonl(path, records):
    with open(path, 'a') as fp:
        for r in records:
            fp.write(json.dumps(r, sort_keys=True) + '\n')
