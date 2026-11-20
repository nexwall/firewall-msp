import importlib.machinery
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = os.path.join(HERE, '..', 'files')
PACKETS = os.path.join(HERE, '..', 'support-packets')

loader = importlib.machinery.SourceFileLoader('ns_support', os.path.join(FILES, 'ns.support'))
spec = importlib.util.spec_from_loader('ns_support', loader)
ns = importlib.util.module_from_spec(spec)
loader.exec_module(ns)


def p(kind, **kw):
    d = {'name': 'x', 'kind': kind, 'required': True}
    d.update(kw)
    return d


class Validate(unittest.TestCase):
    def ok(self, param, value, want):
        self.assertEqual(ns.validate(param, value), want)

    def bad(self, param, value):
        with self.assertRaises(ns.Invalid):
            ns.validate(param, value)

    def test_kinds(self):
        self.ok(p('ip'), '10.0.0.1', '10.0.0.1')
        self.ok(p('ip'), '2001:db8::1', '2001:db8::1')
        self.ok(p('ipv4'), '10.0.0.1', '10.0.0.1')
        self.bad(p('ipv4'), '2001:db8::1')
        self.bad(p('ipv6'), '10.0.0.1')
        self.ok(p('cidr'), '10.0.0.7/24', '10.0.0.0/24')
        self.ok(p('host'), 'example.com', 'example.com')
        self.ok(p('host'), '1.1.1.1', '1.1.1.1')
        self.ok(p('fqdn'), 'a.b-c.example.org.', 'a.b-c.example.org')
        self.ok(p('port'), '443', '443')
        self.bad(p('port'), '0')
        self.bad(p('port'), '65536')
        self.ok(p('int', min=1, max=10), '3', '3')
        self.bad(p('int', min=1, max=10), '11')
        self.ok(p('word'), 'dnsmasq', 'dnsmasq')
        self.ok(p('enum', enum=['tcp', 'udp']), 'tcp', 'tcp')
        self.bad(p('enum', enum=['tcp', 'udp']), 'sctp')

    def test_injection_is_rejected(self):
        for v in ['1.1.1.1; reboot', '$(id)', '`id`', 'a b', 'a\nb', '1.1.1.1|cat', '../etc/passwd', "a'b", 'a"b', '-c1', '\x00', 'é.com']:
            for kind in ('host', 'fqdn', 'ip', 'word', 'port'):
                with self.subTest(v=v, kind=kind):
                    self.bad(p(kind), v)

    def test_default_and_required(self):
        self.ok(p('int', min=1, max=10, default='3', required=False), '', '3')
        self.ok(p('ip', required=False), '', '')
        self.bad(p('ip'), '')
        self.bad(p('ip'), 5)
        self.bad(p('ip'), 'a' * 300)
        self.bad(p('weird'), 'x')


class Run(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.lock = os.path.join(self.dir, 'lock')

    def tearDown(self):
        self.tmp.cleanup()

    def packet(self, pid, script, params=None, timeout=5, max_output=1000, cleanup=''):
        with open(os.path.join(self.dir, pid + '.sh'), 'w') as f:
            f.write('#!/bin/sh\n' + script + '\n')
        with open(os.path.join(self.dir, pid + '.json'), 'w') as f:
            json.dump({'id': pid, 'class': 'R0', 'timeout_sec': timeout, 'max_output': max_output, 'cleanup': cleanup, 'params': params or []}, f)

    def run_(self, req):
        return ns.run(req, base=self.dir, lock_file=self.lock)

    def test_args_are_argv_not_shell(self):
        self.packet('echo-it', 'echo "[$1]"', [p('word')])
        r = self.run_({'id': 'echo-it', 'args': ['abc']})
        self.assertEqual((r['code'], r['stdout']), (0, '[abc]\n'))
        self.assertIn('error', self.run_({'id': 'echo-it', 'args': ['a;id']}))

    def test_unknown_and_traversal(self):
        for pid in ['nope', '../x', 'a/b', '', None, 5, 'A', '-x']:
            self.assertEqual(self.run_({'id': pid}).get('error'), 'unknown packet', pid)

    def test_arg_count(self):
        self.packet('one', 'true', [p('word')])
        self.assertIn('error', self.run_({'id': 'one', 'args': ['a', 'b']}))
        self.assertIn('error', self.run_({'id': 'one', 'args': 'a'}))
        self.assertIn('error', self.run_({'id': 'one'}))

    def test_timeout_kills_group(self):
        self.packet('slow', 'sleep 30 & sleep 30', timeout=1)
        r = self.run_({'id': 'slow'})
        self.assertTrue(r['timed_out'])
        self.assertEqual(r['code'], 124)
        self.assertLess(r['duration_ms'], 4000)

    def test_output_cap(self):
        self.packet('loud', 'yes aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', max_output=500, timeout=10)
        r = self.run_({'id': 'loud'})
        self.assertTrue(r['truncated'])
        self.assertEqual(len(r['stdout']), 500)

    def test_exit_code_and_stderr(self):
        self.packet('fail', 'echo oops >&2; exit 3')
        r = self.run_({'id': 'fail'})
        self.assertEqual((r['code'], r['stderr'].strip()), (3, 'oops'))

    def test_environment_is_clean(self):
        os.environ['SECRET_TEST'] = 'leak'
        self.packet('env', 'echo "$SECRET_TEST"; echo "$PATH"')
        r = self.run_({'id': 'env'})
        self.assertTrue(r['stdout'].startswith('\n/usr/sbin'))

    def test_one_at_a_time(self):
        self.packet('slow2', 'sleep 2', timeout=5)
        self.packet('fast', 'true')
        import threading
        t = threading.Thread(target=lambda: self.run_({'id': 'slow2'}))
        t.start()
        import time
        time.sleep(0.5)
        self.assertEqual(self.run_({'id': 'fast'}).get('error'), 'another support packet is running')
        t.join()
        self.assertEqual(self.run_({'id': 'fast'})['code'], 0)

    def test_cleanup_runs_after_failure_and_timeout(self):
        marker = os.path.join(self.dir, 'cleaned')
        self.packet('c1', 'exit 4', cleanup='echo x >> %s' % marker)
        self.packet('c2', 'sleep 30', timeout=1, cleanup='echo x >> %s' % marker)
        self.assertEqual(self.run_({'id': 'c1'})['code'], 4)
        self.assertTrue(self.run_({'id': 'c2'})['timed_out'])
        with open(marker) as f:
            self.assertEqual(f.read().count('x'), 2)

    def test_list(self):
        self.packet('b-one', 'true')
        self.packet('a-one', 'true')
        self.assertEqual([x['id'] for x in ns.list_packets(self.dir)['packets']], ['a-one', 'b-one'])


class Shipped(unittest.TestCase):
    def test_every_packet_is_consistent(self):
        ids = sorted(f[:-5] for f in os.listdir(PACKETS) if f.endswith('.json'))
        self.assertEqual(len(ids), 26)
        for pid in ids:
            meta, script = ns.load(pid, PACKETS)
            self.assertEqual(meta['id'], pid)
            self.assertIn(meta['class'], ('R0', 'R1'))
            self.assertGreater(meta['timeout_sec'], 0)
            self.assertEqual(subprocess.run(['sh', '-n', script]).returncode, 0, pid)

    def test_packets_are_read_only(self):
        forbidden = ['reboot', 'poweroff', 'halt', 'rm ', 'uci set', 'uci commit', 'uci delete', 'mv ', 'chmod', 'kill ', 'sysupgrade',
                     'chpasswd', 'opkg', 'wget', 'curl -o', ' restart', ' stop ', 'iptables -A', 'nft add', 'nft delete', 'nft flush']
        for f in os.listdir(PACKETS):
            if f.endswith('.sh'):
                with open(os.path.join(PACKETS, f)) as fh:
                    text = fh.read()
                for action in re.findall(r'/etc/init\.d/\S+\s+(\w+)', text):
                    self.assertIn(action, ('status', 'info', 'enabled'), f)
                for bad in forbidden:
                    if f == 'support-package.sh' and bad == 'rm ':
                        # it only removes its own fixed work folder under /tmp
                        self.assertEqual(text.count('rm -rf "$D"'), 2)
                        self.assertNotIn('rm -rf /', text)
                        continue
                    self.assertNotIn(bad, text, '%s uses %r' % (f, bad))

    def test_matches_controller_catalog_when_available(self):
        cat = os.path.join(HERE, '..', '..', '..', '..', 'nexwall-controller', 'api', 'support', 'catalog.json')
        if not os.path.exists(cat):
            self.skipTest('controller catalog not next to this tree')
        for e in json.load(open(cat)):
            meta, _ = ns.load(e['id'], PACKETS)
            self.assertEqual([q['name'] for q in meta['params']], [q['name'] for q in e['params']])


if __name__ == '__main__':
    unittest.main()
