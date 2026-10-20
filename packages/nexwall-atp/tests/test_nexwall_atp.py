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


def entry(host, i, period, start, other='203.0.113.9', port=8443, origin=True):
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
        self.assertEqual((st['enabled'], st['entitled'], st['interval']), (True, True, 60))

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

    def test_outside_loopback_and_firewall_own_addresses_are_ignored(self):
        self.put_model()
        self.put_flows([entry('8.8.8.8', i, 60, 5000 - 2400) for i in range(40)] + [entry('192.168.1.1', i, 60, 5000 - 2400) for i in range(40)]
                       + [entry('127.0.0.1', i, 60, 5000 - 2400) for i in range(40)])
        svc = self.service()
        svc.own, svc.own_at = {'192.168.1.1'}, 5000.0
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

    def test_client_flows_with_local_origin_true_are_scored(self):
        # on a real unit local_origin is true for the connections the client opened
        self.put_model()
        self.put_flows([entry('192.168.1.50', i, 60, 5000 - 2400, origin=True) for i in range(40)])
        svc = self.service()
        svc.own, svc.own_at = {'192.168.1.1'}, 5000.0
        self.assertEqual([e['host'] for e in svc.cycle()], ['192.168.1.50'])

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


def make_keys(tmp):
    from Crypto.PublicKey import RSA
    key = RSA.generate(2048)
    pub = os.path.join(tmp, 'pubkey.pem')
    with open(pub, 'wb') as fp:
        fp.write(key.publickey().export_key())
    return key, pub


def signed(key, manifest):
    import base64 as b64
    from Crypto.Hash import SHA256
    from Crypto.Signature import pkcs1_15
    payload = json.dumps(manifest).encode()
    return {'entitled': True, 'license_state': 'subscribed', 'payload': b64.b64encode(payload).decode(),
            'signature': b64.b64encode(pkcs1_15.new(key).sign(SHA256.new(payload))).decode()}


@unittest.skipUnless(importlib.util.find_spec('Crypto'), 'pycryptodome is needed for the signature checks')
class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.mod = load(self.tmp)
        self.key, self.mod.PUBKEY = make_keys(self.tmp)
        self.model = toy_model(self.mod)
        self.raw = json.dumps(self.model).encode()

    def manifest(self, version='2026.10.20.1', raw=None, kind='atp-model', model_version=None):
        import hashlib as h
        raw = raw or self.raw
        return {'kind': kind, 'version': version, 'model': {'model_version': model_version or self.model['version']},
                'files': {'model.json': {'size': len(raw), 'sha256': h.sha256(raw).hexdigest()}}}

    def fetcher(self, resp, data):
        calls = []

        def fetch(path):
            calls.append(path)
            return json.dumps(resp).encode() if 'manifest' in path else data
        fetch.calls = calls
        return fetch

    def do_update(self, resp, data=None, **kw):
        f = self.fetcher(resp, self.raw if data is None else data)
        return self.mod.cmd_update(force=True, fetch_fn=f, now=1000, **kw), f

    def test_a_signed_model_is_installed_and_the_previous_one_is_kept(self):
        rc, f = self.do_update(signed(self.key, self.manifest()))
        self.assertEqual(rc, 0)
        self.assertEqual(open(os.path.join(self.tmp, 'model.json'), 'rb').read(), self.raw)
        newer = dict(self.model, version='2')
        raw2 = json.dumps(newer).encode()
        rc, _ = self.do_update(signed(self.key, self.manifest('2026.10.21.1', raw2, model_version='2')), raw2)
        self.assertEqual(rc, 0)
        self.assertEqual(json.load(open(os.path.join(self.tmp, 'model.json')))['version'], '2')
        self.assertEqual(open(os.path.join(self.tmp, 'model.prev.json'), 'rb').read(), self.raw)
        self.assertEqual(self.mod.cmd_rollback(), 0)
        self.assertEqual(open(os.path.join(self.tmp, 'model.json'), 'rb').read(), self.raw)

    def test_the_same_version_is_not_downloaded_again(self):
        self.do_update(signed(self.key, self.manifest()))
        rc, f = self.do_update(signed(self.key, self.manifest()))
        self.assertEqual((rc, f.calls), (0, ['/api/v1/atp/manifest']))

    def test_a_tampered_model_a_bad_signature_and_a_wrong_kind_are_refused(self):
        rc, _ = self.do_update(signed(self.key, self.manifest()), data=self.raw + b' ')
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'model.json')))
        other, _ = make_keys(tempfile.mkdtemp())
        rc, _ = self.do_update(signed(other, self.manifest()))
        self.assertEqual(rc, 1)
        rc, _ = self.do_update(signed(self.key, self.manifest(kind='threat-feeds')))
        self.assertEqual(rc, 1)
        rc, _ = self.do_update(signed(self.key, self.manifest(model_version='other')))
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'model.json')))
        self.assertIn('failed', load_state(self.tmp, 'update.json')['last_result'])

    def test_an_unusable_model_is_refused_even_when_signed(self):
        bad = json.dumps({'format': 1}).encode()
        rc, _ = self.do_update(signed(self.key, self.manifest(raw=bad)), data=bad)
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'model.json')))

    def test_not_entitled_and_nothing_published(self):
        rc, _ = self.do_update({'entitled': False, 'license_state': 'unlicensed'})
        self.assertEqual(rc, 3)
        rc, _ = self.do_update({'entitled': True, 'license_state': 'subscribed'})
        self.assertEqual(rc, 2)

    def test_the_installed_model_stays_when_the_server_cannot_be_reached(self):
        self.do_update(signed(self.key, self.manifest()))

        def down(path):
            raise RuntimeError('could not reach the server')
        self.assertEqual(self.mod.cmd_update(force=True, fetch_fn=down, now=2000), 1)
        self.assertEqual(open(os.path.join(self.tmp, 'model.json'), 'rb').read(), self.raw)


def load_state(tmp, name):
    with open(os.path.join(tmp, name)) as fp:
        return json.load(fp)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.mod = load(self.tmp)
        self.sent = []
        self.now = 1792459000

    def put_events(self, *events):
        with open(os.path.join(self.tmp, 'events.jsonl'), 'w') as fp:
            for ev in events:
                fp.write(json.dumps(ev) + '\n')

    def event(self, indicators, host='192.168.1.50'):
        return {'layer': 'atp', 'host': host, 'level': 'high', 'ts': self.now - 100, 'indicators': indicators}

    def post(self, path, doc):
        self.sent.append((path, doc))

    def report(self, **kw):
        return self.mod.cmd_report(force=True, post_fn=self.post, now=self.now, **kw)

    def test_only_remote_public_indicators_are_sent_never_the_host(self):
        self.put_events(self.event([{'type': 'ip', 'value': '8.8.4.4', 'beacon': 0.97}, {'type': 'ip', 'value': '192.168.1.9', 'beacon': 0.9},
                                    {'type': 'ip', 'value': '10.0.0.1', 'beacon': 0.9}, {'type': 'domain', 'value': 'qzxvbnmkrtplwq.net', 'dga': 0.99},
                                    {'type': 'domain', 'value': 'printer.lan', 'dga': 0.95}, {'type': 'domain', 'value': 'nas.local', 'dga': 0.95},
                                    {'type': 'domain', 'value': '8.8.8.8', 'dga': 0.9}, {'type': 'url', 'value': 'http://x.example.net/a?b=1'}, 'junk']))
        self.assertEqual(self.report(), 0)
        path, doc = self.sent[0]
        self.assertEqual(path, '/api/v1/atp/report')
        self.assertEqual(sorted((i['type'], i['value']) for i in doc['indicators']), [('domain', 'qzxvbnmkrtplwq.net'), ('ip', '8.8.4.4')])
        text = json.dumps(doc)
        for secret in ('192.168.1.50', '192.168.1.9', '10.0.0.1', 'printer', 'nas.local', 'host'):
            self.assertNotIn(secret, text)
        self.assertEqual(set(doc), {'version', 'day', 'model_version', 'indicators'})

    def test_nothing_is_sent_when_sharing_is_off(self):
        self.put_events(self.event([{'type': 'ip', 'value': '8.8.4.4', 'beacon': 0.97}]))
        self.mod.settings = lambda: {'enabled': True, 'share': False, 'interval': 60, 'max_hosts': 200, 'budget': 2.0}
        self.assertEqual(self.report(), 3)
        self.assertEqual(self.sent, [])

    def test_nothing_is_sent_when_not_licensed(self):
        self.put_events(self.event([{'type': 'ip', 'value': '8.8.4.4', 'beacon': 0.97}]))
        os.environ.pop('ATP_NO_LICENSE')
        try:
            self.assertEqual(self.report(), 3)
        finally:
            os.environ['ATP_NO_LICENSE'] = '1'
        self.assertEqual(self.sent, [])

    def test_the_same_report_is_not_sent_twice_and_a_failure_is_retried(self):
        self.put_events(self.event([{'type': 'ip', 'value': '8.8.4.4', 'beacon': 0.97}]))
        self.assertEqual(self.report(), 0)
        self.assertEqual(self.report(), 0)
        self.assertEqual(len(self.sent), 1)

        def broken(path, doc):
            raise RuntimeError('server down')
        self.put_events(self.event([{'type': 'ip', 'value': '8.8.8.8', 'beacon': 0.97}]))
        self.assertEqual(self.mod.cmd_report(force=True, post_fn=broken, now=self.now), 1)
        self.assertEqual(self.report(), 0)
        self.assertEqual(len(self.sent), 2)

    def test_no_indicators_means_no_report(self):
        self.put_events(self.event([]))
        self.assertEqual(self.report(), 0)
        self.assertEqual(self.sent, [])

    def test_old_events_are_not_reported(self):
        ev = self.event([{'type': 'ip', 'value': '8.8.4.4', 'beacon': 0.97}])
        ev['ts'] = self.now - 3 * 86400
        self.put_events(ev)
        self.assertEqual(self.report(), 0)
        self.assertEqual(self.sent, [])


class SettingsAndStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.mod = load(self.tmp)
        self.values = {}
        self.mod.uci = lambda key, default: self.values.get(key, default)

    def test_defaults_collective_and_sharing_on_updates_every_six_hours(self):
        c = self.mod.settings()
        self.assertEqual((c['enabled'], c['collective'], c['share'], c['auto_update'], c['update_hours']), (True, True, True, True, 6))

    def test_update_hours_only_takes_the_offered_values(self):
        for given, want in (('1', 1), ('24', 24), ('7', 6), ('abc', 6), ('0', 6)):
            self.values['nexwall_atp.main.update_hours'] = given
            self.assertEqual(self.mod.settings()['update_hours'], want)

    def test_the_update_interval_follows_the_choice_and_never_goes_below_the_servers_minimum(self):
        self.assertEqual(self.mod.update_interval({'update_hours': 12}), 12 * 3600)
        self.assertEqual(self.mod.update_interval({'update_hours': 0}), self.mod.UPDATE_MIN_INTERVAL)

    def test_automatic_updates_off_means_sync_does_not_look_but_update_now_does(self):
        self.values['nexwall_atp.main.auto_update'] = '0'
        calls = []
        self.assertEqual(self.mod.cmd_update(force=False, fetch_fn=lambda p: calls.append(p) or b'{}'), 0)
        self.assertEqual(calls, [])
        self.mod.cmd_update(force=True, fetch_fn=lambda p: calls.append(p) or b'{"entitled": false}')
        self.assertEqual(calls, ['/api/v1/atp/manifest'])

    def test_a_recent_update_check_is_not_repeated_before_the_chosen_interval(self):
        self.mod.save_json('update.json', {'last_check': 1000, 'version': '2026.10.20.1'})
        calls = []
        self.values['nexwall_atp.main.update_hours'] = '12'
        self.assertEqual(self.mod.cmd_update(force=False, fetch_fn=lambda p: calls.append(p) or b'{}', now=1000 + 11 * 3600), 0)
        self.assertEqual(calls, [])

    def test_collective_off_stops_the_reports_even_with_sharing_on(self):
        self.values['nexwall_atp.main.collective'] = '0'
        sent = []
        os.makedirs(self.tmp, exist_ok=True)
        with open(os.path.join(self.tmp, 'events.jsonl'), 'w') as fp:
            fp.write(json.dumps({'layer': 'atp', 'host': '192.168.1.5', 'level': 'high', 'ts': 1792459000 - 10, 'indicators': [{'type': 'ip', 'value': '8.8.4.4', 'beacon': 0.9}]}) + '\n')
        self.assertEqual(self.mod.cmd_report(force=True, post_fn=lambda p, d: sent.append(d), now=1792459000), 3)
        self.assertEqual(sent, [])

    def test_status_carries_the_current_settings_the_update_and_the_report(self):
        self.mod.save_json('update.json', {'last_result': 'installed 2026.10.20.1', 'version': '2026.10.20.1'})
        self.mod.save_json('report.json', {'last_sent': 5, 'last_result': 'sent 2 indicator(s)'})
        self.mod.save_json('status.json', {'state': 'scoring', 'enabled': True, 'ts': 1, 'pid': 1})
        self.values['nexwall_atp.main.enabled'] = '0'            # switched off just now: the status shows it before the service has stopped
        st = self.mod.read_status()
        self.assertEqual((st['state'], st['enabled'], st['update']['version'], st['report']['last_sent']), ('scoring', False, '2026.10.20.1', 5))

    def test_status_of_a_service_that_never_ran(self):
        st = self.mod.read_status()
        self.assertEqual((st['state'], st['enabled'], st['collective']), ('not_running', True, True))

    def test_errors_carry_their_time_and_the_status_has_the_pid_and_the_model_details(self):
        self.mod.save_json('update.json', {'last_check': 1792459000 - 100 * 3600})
        with open(os.path.join(self.tmp, 'model.json'), 'w') as fp:
            json.dump(toy_model(self.mod), fp)
        svc = self.mod.Service(cfg=dict(self.mod.settings()), clock=lambda: 1792459000)
        svc.fail('ns.flows did not answer')
        svc.load_model()
        svc.write_status('scoring')
        st = json.load(open(os.path.join(self.tmp, 'status.json')))
        self.assertEqual((st['last_error'], st['last_error_ts'], st['pid']), ('ns.flows did not answer', 1792459000, os.getpid()))
        self.assertEqual(st['model_info']['window'], 900.0)
        self.assertTrue(st['model_stale'])                       # 100 hours without looking for a model while updates are automatic


if __name__ == '__main__':
    unittest.main()
