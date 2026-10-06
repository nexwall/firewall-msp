import importlib.machinery
import importlib.util
import os

HERE = os.path.dirname(__file__)
PATH = os.path.join(HERE, '..', 'files', 'usr', 'sbin', 'ns-flowlog')
loader = importlib.machinery.SourceFileLoader('ns_flowlog', PATH)
spec = importlib.util.spec_from_loader('ns_flowlog', loader)
fl = importlib.util.module_from_spec(spec)
loader.exec_module(fl)

NOW = 1_791_330_000_000


def flow(digest='d1', origin=True, last=NOW - 1000, first=NOW - 61000, lb=1000, ob=5000, app='netify.youtube', **kw):
    f = {'digest': digest, 'digest_prev': [], 'local_origin': origin, 'local_ip': '192.168.1.50', 'other_ip': '142.250.1.1',
         'local_port': 51000, 'other_port': 443, 'local_bytes': lb, 'other_bytes': ob, 'local_mac': 'aa:bb:cc:00:00:01',
         'other_mac': 'aa:bb:cc:00:00:02', 'ip_protocol': 6, 'detected_application_name': app, 'detected_protocol_name': 'TLS',
         'host_server_name': 'www.youtube.com', 'first_seen_at': first, 'last_seen_at': last, 'total_packets': 40}
    f.update(kw)
    return {'type': 'flow_dpi_complete', 'interface': 'wan', 'flow': f}


def test_record_of_a_connection_opened_by_the_local_side():
    r = fl.to_record(flow(), 'ended')
    assert r['src_ip'] == '192.168.1.50' and r['dst_ip'] == '142.250.1.1' and r['src_port'] == '51000' and r['dst_port'] == '443'
    assert r['bytes_out'] == '1000' and r['bytes_in'] == '5000' and r['proto'] == 'TCP'
    assert r['application'] == 'netify.youtube' and r['host'] == 'www.youtube.com' and r['duration_ms'] == '60000'
    assert r['app_name'] == 'nexwall-flow' and r['state'] == 'ended' and r['interface'] == 'wan' and r['src_mac'] == 'aa:bb:cc:00:00:01'
    assert r['_time'].endswith('Z') and 'netify.youtube' in r['_msg'] and '192.168.1.50:51000 -> 142.250.1.1:443' in r['_msg']


def test_record_of_a_connection_opened_from_outside_swaps_the_sides():
    r = fl.to_record(flow(origin=False), 'ended')
    assert r['src_ip'] == '142.250.1.1' and r['dst_ip'] == '192.168.1.50' and r['src_port'] == '443'
    assert r['bytes_out'] == '5000' and r['bytes_in'] == '1000' and r['src_mac'] == 'aa:bb:cc:00:00:02'


def test_active_records_are_stamped_with_the_snapshot_time():
    assert fl.to_record(flow(last=NOW - 5000), 'active', NOW)['_time'] == fl.iso(NOW)


def test_idle_connection_ends_once():
    t = fl.Tracker()
    assert t.update([flow(last=NOW - 1000)], NOW) == []                     # still active
    ended = t.update([flow(last=NOW - 40000)], NOW + 40000)                  # silent for 40 s
    assert len(ended) == 1
    assert t.update([flow(last=NOW - 40000)], NOW + 50000) == []             # still listed by ns-flows: not reported again


def test_connection_that_leaves_the_table_ends():
    t = fl.Tracker()
    t.update([flow('a'), flow('b')], NOW)
    ended = t.update([flow('b')], NOW + 10000)
    assert [e['flow']['digest'] for e in ended] == ['a']


def test_rekeyed_flow_is_not_counted_twice():
    t = fl.Tracker()
    t.update([flow('old')], NOW)
    assert t.update([flow('new', digest_prev=['old', 'new'])], NOW + 10000) == []
    assert list(t.live) == ['new']


def test_tombstones_expire():
    t = fl.Tracker()
    t.update([flow(last=NOW - 40000)], NOW)
    assert t.done
    t.update([], NOW + (fl.TOMBSTONE_S + 1) * 1000)
    assert not t.done


def test_snapshot_lists_open_connections_biggest_first_and_limits():
    t = fl.Tracker()
    items = [flow('small', lb=10, ob=10), flow('big', lb=10_000, ob=90_000), flow('old', last=NOW - 90000)]
    snap = t.snapshot(items, NOW)
    assert [s['flow']['digest'] for s in snap] == ['big', 'small']
    many = [flow('f%d' % i) for i in range(fl.SNAPSHOT_MAX + 50)]
    assert len(fl.Tracker().snapshot(many, NOW)) == fl.SNAPSHOT_MAX


class Rig:
    def __init__(self):
        self.t = 1000.0
        self.count = 0
        self.vl_up = True
        self.table = []
        self.reads = 0
        self.written = []
        self.ok = True
        self.svc = fl.Service(now=lambda: self.t, sleep=lambda s: None, counter=self.counter, flows=self.flows, write=self.write)

    def counter(self):
        return self.count if self.vl_up else None

    def flows(self):
        self.reads += 1
        return self.table

    def write(self, recs):
        if self.ok:
            self.written += recs
        return self.ok


def test_closed_viewer_costs_nothing_and_never_reads_the_flow_table():
    r = Rig()
    r.table = [flow()]
    for _ in range(5):
        r.t += 15
        assert r.svc.step() == 0
    assert r.reads == 0 and not r.written


def test_opening_the_viewer_writes_the_snapshot_then_ended_connections():
    r = Rig()
    r.svc.step()                                       # baseline of the counter
    r.count += 1                                       # a query arrived: the page is open
    r.table = [flow('a', last=int(r.t * 1000) - 1000), flow('b', last=int(r.t * 1000) - 2000)]
    assert r.svc.step() == 2 and {w['state'] for w in r.written} == {'active'}
    r.t += 10
    r.table = [r.table[1]]                             # connection a is gone
    assert r.svc.step() == 1 and r.written[-1]['state'] == 'ended' and r.written[-1]['_msg'].startswith('netify.youtube')


def test_viewer_counts_as_closed_after_the_grace_period_and_reopens_with_a_new_snapshot():
    r = Rig()
    r.svc.step(); r.count += 1
    r.table = [flow('a', last=int(r.t * 1000))]
    assert r.svc.step() == 1
    r.t += fl.GRACE + 1                                # nobody queried for longer than the grace
    assert r.svc.step() == 0 and not r.svc.open
    reads = r.reads
    r.t += 30
    assert r.svc.step() == 0 and r.reads == reads      # closed: not even read
    r.count += 1
    r.table = [flow('c', last=int(r.t * 1000))]
    assert r.svc.step() == 1 and r.written[-1]['state'] == 'active'


def test_victorialogs_down_or_flow_table_down_is_harmless():
    r = Rig()
    r.svc.step(); r.count += 1
    r.vl_up = False
    assert r.svc.step() == 0
    r.vl_up = True
    r.count += 1
    r.svc.flows = lambda: (_ for _ in ()).throw(OSError('ns-flows is down'))
    assert r.svc.step() == 0


def test_write_failure_does_not_crash():
    r = Rig()
    r.svc.step(); r.count += 1
    r.table = [flow('a', last=int(r.t * 1000))]
    r.ok = False
    assert r.svc.step() == 0
