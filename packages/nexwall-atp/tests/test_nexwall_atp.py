import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, '..', 'files', 'nexwall-atp')
LIB = os.path.join(HERE, '..', 'files', 'lib')


def load(tmp):
    os.environ.update(ATP_DIR=tmp, ATP_LIB=LIB, ATP_NO_LICENSE='1')
    for m in [m for m in sys.modules if m == 'atp' or m.startswith('atp.')]:
        del sys.modules[m]
    loader = importlib.machinery.SourceFileLoader('nexwall_atp', SCRIPT)
    spec = importlib.util.spec_from_loader('nexwall_atp', loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def toy_model(mod):
    from atp.netintel import flowfeatures as ff
    names = [k for k in ff.FEATURE_NAMES if k != 'window']
    coef = [0.0] * len(names)
    coef[names.index('beacon_max')] = 6.0
    return {'format': 1, 'name': 'toy', 'version': '1', 'window': 900.0, 'history_windows': 2, 'beacon_min_events': 4, 'beacon_full_events': 15,
            'features': names, 'mean': [0.0] * len(names), 'std': [1.0] * len(names), 'coef': coef, 'intercept': -3.0, 'thresholds': {'review': 0.6, 'high': 0.9}}


def entry(host, i, period, start, other='203.0.113.9', port=8443, origin=False):
    first = (start + i * period) * 1000
    return {'interface': 'lan', 'flow': {'digest': '%s-%d' % (host, i), 'local_ip': host, 'other_ip': other, 'other_port': port, 'ip_protocol': 6,
            'first_seen_at': first, 'last_seen_at': first + 1000, 'local_bytes': 400, 'other_bytes': 300, 'local_packets': 4, 'other_packets': 3,
            'local_origin': origin}}


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.mod = load(self.tmp)

    def put_flows(self, entries):
        p = os.path.join(self.tmp, 'flows.json')
        with open(p, 'w') as fp:
            json.dump({'flows': entries}, fp)
        os.environ['FLOWS_JSON'] = p

    def put_model(self, m=None):
        with open(os.path.join(self.tmp, 'model.json'), 'w') as fp:
            json.dump(m or toy_model(self.mod), fp)

    def service(self, now=5000.0):
        return self.mod.Service(cfg={'enabled': True, 'interval': 60, 'max_hosts': 200, 'budget': 2.0}, clock=lambda: now)

    def test_no_model_means_no_events_and_a_status(self):
        self.put_flows([])
        svc = self.service()
        self.assertEqual(svc.cycle(), [])
        self.assertEqual(json.load(open(os.path.join(self.tmp, 'status.json')))['state'], 'no_model')

    def test_a_beaconing_host_becomes_an_advisory_event(self):
        self.put_model()
        self.put_flows([entry('192.168.1.50', i, 60, 5000 - 2400) for i in range(40)])
        svc = self.service()
        ev = svc.cycle()
        self.assertEqual([e['host'] for e in ev], ['192.168.1.50'])
        self.assertEqual(ev[0]['layer'], 'atp')
        self.assertIn(ev[0]['level'], ('review', 'high'))
        lines = open(os.path.join(self.tmp, 'events.jsonl')).read().splitlines()
        self.assertEqual(len(lines), 1)
        st = json.load(open(os.path.join(self.tmp, 'status.json')))
        self.assertEqual((st['state'], st['model'], st['hosts']), ('scoring', 'toy', 1))

    def test_same_host_is_not_written_again_inside_a_window(self):
        self.put_model()
        self.put_flows([entry('192.168.1.50', i, 60, 5000 - 2400) for i in range(40)])
        t = [5000.0]
        svc = self.mod.Service(cfg={'enabled': True, 'interval': 60, 'max_hosts': 200, 'budget': 2.0}, clock=lambda: t[0])
        self.assertEqual(len(svc.cycle()), 1)
        t[0] += 60
        self.assertEqual(svc.cycle(), [])
        t[0] += 900
        self.assertEqual(len(svc.cycle()), 1)

    def test_outside_and_firewall_own_flows_are_ignored(self):
        self.put_model()
        self.put_flows([entry('8.8.8.8', i, 60, 5000 - 2400) for i in range(40)] + [entry('192.168.1.1', i, 60, 5000 - 2400, origin=True) for i in range(40)]
                       + [entry('127.0.0.1', i, 60, 5000 - 2400) for i in range(40)])
        svc = self.service()
        self.assertEqual(svc.cycle(), [])
        self.assertEqual(svc.scorer.flows, {})

    def test_broken_model_is_reported_not_used(self):
        self.put_model({'format': 1})
        self.put_flows([])
        svc = self.service()
        self.assertEqual(svc.cycle(), [])
        self.assertIn('model', svc.stats['last_error'])

    def test_flows_that_cannot_be_read_do_not_stop_the_cycle(self):
        self.put_model()
        os.environ['FLOWS_JSON'] = os.path.join(self.tmp, 'missing.json')
        svc = self.service()
        self.assertEqual(svc.cycle(), [])
        self.assertEqual(svc.stats['last_error'], 'ns.flows did not answer')

    def test_events_file_is_bounded(self):
        self.put_model()
        self.put_flows([])
        svc = self.service()
        path = os.path.join(self.tmp, 'events.jsonl')
        with open(path, 'w') as fp:
            fp.write('x' * (self.mod.MAX_EVENTS_BYTES + 1))
        svc.write_events([{'a': 1}])
        self.assertTrue(os.path.exists(path + '.1'))
        self.assertEqual(open(path).read().strip(), '{"a": 1}')

    def test_event_has_no_internal_address_in_its_indicators(self):
        self.put_model()
        self.put_flows([entry('192.168.1.50', i, 60, 5000 - 2400) for i in range(40)])
        ev = self.service().cycle()[0]
        self.assertEqual([i['value'] for i in ev['indicators'] if i['type'] == 'ip'], ['203.0.113.9'])
        self.assertNotIn('192.168.1.50', json.dumps(ev['indicators']))


class ReadFlowsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.mod = load(self.tmp)
        os.environ.pop('FLOWS_JSON', None)
        self.mod.FLOWS_URL = 'http://127.0.0.1:9/flows'       # nothing listens there
        self._run = self.mod.subprocess.run
        self.addCleanup(setattr, self.mod.subprocess, 'run', self._run)     # the module object is the shared subprocess module

    def test_every_page_is_read_when_the_daemon_is_not_there(self):
        pages = {1: {'flows': [1, 2], 'last_page': 3}, 2: {'flows': [3], 'last_page': 3}, 3: {'flows': [4], 'last_page': 3}}
        calls = []

        class P:
            def __init__(self, out):
                self.stdout = out

        def fake_run(cmd, **kw):
            arg = json.loads(cmd[-1])
            calls.append(arg)
            return P(json.dumps(pages[arg['page']]))
        self.mod.subprocess.run = fake_run
        self.assertEqual(self.mod.read_flows(), [1, 2, 3, 4])
        self.assertEqual([c['page'] for c in calls], [1, 2, 3])

    def test_nothing_answering_is_none(self):
        class P:
            stdout = ''
        self.mod.subprocess.run = lambda *a, **k: P()
        self.assertIsNone(self.mod.read_flows())


if __name__ == '__main__':
    unittest.main()
