import importlib.machinery
import importlib.util
import json
import os
import time

import pytest

SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'files', 'nexwall-usage')


@pytest.fixture()
def mod(tmp_path, monkeypatch):
    monkeypatch.setenv('USAGE_DIR', str(tmp_path / 'usage'))
    monkeypatch.setenv('SYS_NET', str(tmp_path / 'net'))
    loader = importlib.machinery.SourceFileLoader('nexwall_usage', SCRIPT)
    spec = importlib.util.spec_from_loader('nexwall_usage', loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


UCI_FW = """firewall.ns_lan=zone
firewall.ns_lan.name='lan'
firewall.ns_lan.network='lan'
firewall.ns_guest=zone
firewall.ns_guest.name='guest'
firewall.ns_guest.network='guest'
firewall.ns_wan=zone
firewall.ns_wan.name='wan'
firewall.ns_wan.network='wan' 'WAN2'
firewall.ns_rw=zone
firewall.ns_rw.name='rwopenvpn'
firewall.ns_rw.device='tunrw+'
firewall.ns_s2s=zone
firewall.ns_s2s.name='ipsec'
firewall.ns_s2s.network='ipsec1'
firewall.ns_wg=zone
firewall.ns_wg.name='wg_branches'
firewall.ns_wg.network='wg0'
firewall.ns_lan_to_wan=rule
firewall.ns_lan_to_wan.name='LAN -> WAN'
"""
UCI_NW = """network.lan=interface
network.lan.proto='static'
network.lan.device='br-lan'
network.guest=interface
network.guest.proto='static'
network.guest.device='br-guest'
network.wan=interface
network.wan.proto='dhcp'
network.wan.device='eth1'
network.wg0=interface
network.wg0.proto='wireguard'
network.ipsec1=interface
network.ipsec1.proto='none'
network.ipsec1.device='ipsec0'
"""


def topo(mod):
    fw, nw = mod.parse_uci_show(UCI_FW), mod.parse_uci_show(UCI_NW)
    zones = [{'name': o['name'], 'networks': ([o['network']] if isinstance(o.get('network'), str) else o.get('network', [])),
              'devices': ([o['device']] if isinstance(o.get('device'), str) else o.get('device', []))} for o in fw.values() if o.get('.type') == 'zone']
    nets = {k.split('.', 1)[1]: {'proto': o.get('proto', ''), 'device': o.get('device', '')} for k, o in nw.items() if o.get('.type') == 'interface'}
    return zones, nets


def test_percentile(mod):
    assert mod.percentile([], 95) == 0
    assert mod.percentile([5], 95) == 5
    assert mod.percentile(list(range(1, 101)), 95) == 95
    assert mod.percentile([1, 2, 3, 4, 100], 95) == 100


def test_parse_uci_show_lists_and_types(mod):
    fw = mod.parse_uci_show(UCI_FW)
    assert fw['firewall.ns_wan']['.type'] == 'zone'
    assert fw['firewall.ns_wan']['network'] == ['wan', 'WAN2']
    assert fw['firewall.ns_lan']['network'] == 'lan'


def test_inner_interfaces_exclude_wan_and_tunnels(mod):
    zones, nets = topo(mod)
    names, devs = mod.inner_interfaces(zones, nets)
    assert {'lan', 'guest', 'rwopenvpn'} <= names          # guest counts, OpenVPN remote access counts
    assert not ({'wan', 'WAN2', 'ipsec', 'ipsec1', 'wg0', 'wg_branches'} & names)   # IPsec and WireGuard are not measured
    assert devs == {'br-lan', 'br-guest', 'tunrw+'}


def test_expand_devices_drops_tunnels(mod):
    got = mod.expand_devices({'br-lan', 'tunrw+', 'wg0', 'tunsec', 'br-missing'}, {'br-lan', 'tunrw1', 'tunrw2', 'wg0', 'tunsec', 'eth1'})
    assert got == {'br-lan', 'tunrw1', 'tunrw2'}


def flow(ip, mac='aa:bb:cc:00:00:01', iface='wan', origin=True):
    """A flow as the flow daemon of a real unit reports it: labelled with the capture role (`wan`) and `local_origin` true (the local side opened it)."""
    return {'interface': iface, 'flow': {'local_ip': ip, 'local_mac': mac, 'local_origin': origin}}


def nets(*cidrs):
    import ipaddress
    return [ipaddress.ip_network(c) for c in cidrs]


def test_count_flows_rules(mod):
    items = [flow('192.168.1.10', 'aa:00:00:00:00:01'), flow('192.168.1.10', 'aa:00:00:00:00:01'),      # same device twice
             flow('192.168.1.11', 'aa:00:00:00:00:01'),                                                  # same MAC with a new IP: still one device
             flow('192.168.1.12', '00:00:00:00:00:00'), flow('192.168.1.12', '00:00:00:00:00:00'),      # no MAC: by IP
             flow('192.168.1.1'),                                                                        # the firewall itself
             flow('192.168.0.136'),                                                                      # the firewall's WAN address
             flow('192.168.0.8', 'aa:00:00:00:00:08'),                                                   # a host on the Internet-facing subnet (private range too)
             flow('203.0.113.5'),                                                                        # a public address is never an internal device
             flow('10.5.0.7', 'aa:00:00:00:00:07'),                                                      # private address routed in from behind a LAN router: by IP
             flow('10.9.0.2', 'aa:00:00:00:00:09')]                                                      # OpenVPN remote-access user
    ids = mod.count_flows(items, nets('192.168.1.0/24', '10.9.0.0/24'), {'192.168.1.1', '192.168.0.136'}, 'salt',
                          vpn_nets=nets('10.9.0.0/24'), outer_nets=nets('192.168.0.0/24'))
    assert len(ids) == 5          # .10/.11 (one MAC), .12, 10.5.0.7, 10.9.0.2
    assert sum(1 for v in ids.values() if v) == 1


def test_the_interface_name_and_local_origin_do_not_matter(mod):
    # every flow of a real unit says interface "wan"; whatever the label, the address decides
    for iface in ('wan', 'lan', 'nfq0', ''):
        for origin in (True, False):
            ids = mod.count_flows([flow('192.168.1.20', iface=iface, origin=origin)], nets('192.168.1.0/24'), {'192.168.1.1'}, 'salt')
            assert len(ids) == 1


def test_ids_are_hashed(mod):
    ids = mod.count_flows([flow('192.168.1.10')], nets('192.168.1.0/24'), set(), 'salt')
    key = next(iter(ids))
    assert '192.168' not in key and len(key) == 12
    assert mod.device_id({'local_ip': '1.1.1.1', 'local_mac': ''}, 'a') != mod.device_id({'local_ip': '1.1.1.1', 'local_mac': ''}, 'b')


def test_throughput(mod):
    assert mod.mbps(0, 37_500_000, 300) == pytest.approx(1.0)
    assert mod.mbps(10, 5, 300) == 0


def test_day_rollover_and_summary(mod):
    t0 = time.mktime((2026, 10, 19, 10, 0, 0, 0, 0, -1))
    st, days = {}, []
    st, days = mod.update(st, days, t0, {'a': False, 'b': True}, 2.0)
    st, days = mod.update(st, days, t0 + 300, {'a': False, 'c': False}, 8.0)
    assert len(days) == 0 and len(st['ids']) == 3
    st, days = mod.update(st, days, t0 + 86400, {'a': False}, 1.0)        # next day closes the first one
    assert len(days) == 1
    d = days[0]
    assert d['devices'] == 3 and d['vpn_devices'] == 1 and d['peak_mbps'] == 8.0 and d['samples'] == 2
    assert st['ids'] == {'a': False}


def test_summary_window_and_p95(mod):
    days = [{'day': 'd%d' % i, 'devices': i, 'vpn_devices': 0, 'peak_mbps': i, 'p95_mbps': i / 2.0, 'samples': 10} for i in range(1, 41)]
    s = mod.summary(days)
    assert s['observed_days'] == 30 and len(s['days']) == 7
    assert s['p95_devices'] == 39      # last 30 days are 11..40, nearest-rank 95th percentile of 30 values is the 29th: 39
    assert s['peak_mbps'] == 40


def test_sample_end_to_end(mod, tmp_path, monkeypatch):
    net = tmp_path / 'net'
    for d in ('br-lan', 'tunrw1', 'wg0', 'eth1'):
        (net / d / 'statistics').mkdir(parents=True)
        (net / d / 'statistics' / 'rx_bytes').write_text('1000')
        (net / d / 'statistics' / 'tx_bytes').write_text('1000')
    zones, nets = topo(mod)
    (tmp_path / 'topo.json').write_text(json.dumps({'zones': zones, 'networks': nets}))
    flows = {'flows': [flow('192.168.1.10'), flow('192.168.1.11', 'aa:00:00:00:00:02'), flow('10.9.0.2', 'aa:00:00:00:00:09'), flow('192.168.1.1'), flow('192.168.0.136')]}
    (tmp_path / 'flows.json').write_text(json.dumps(flows))
    monkeypatch.setenv('TOPOLOGY_JSON', str(tmp_path / 'topo.json'))
    monkeypatch.setenv('FLOWS_JSON', str(tmp_path / 'flows.json'))
    addr = {'br-lan': '192.168.1.1/24', 'tunrw1': '10.9.0.1/24', 'eth1': '192.168.0.136/24', 'wg0': '10.99.0.1/24'}

    def fake_run(cmd):
        if cmd[:4] == ['ip', '-4', '-o', 'addr']:
            devs = [cmd[-1]] if 'dev' in cmd else list(addr)
            return ''.join('%d: %s    inet %s brd x scope global %s\n' % (i, d, addr[d], d) for i, d in enumerate(devs) if d in addr)
        return ''
    monkeypatch.setattr(mod, '_run', fake_run)
    t = time.mktime((2026, 10, 19, 10, 0, 0, 0, 0, -1))
    mod.sample(t)
    for d in ('br-lan', 'tunrw1'):
        (net / d / 'statistics' / 'rx_bytes').write_text(str(1000 + 18_750_000))
    today = mod.sample(t + 300)
    assert today['devices'] == 3 and today['vpn_devices'] == 1
    assert today['peak_mbps'] == pytest.approx(1.0, rel=0.05)        # 2 x 18.75 MB (wg0 and eth1 are not measured)... 37.5 MB in 300 s = 1 Mbps
    s = json.loads(open(os.path.join(os.environ['USAGE_DIR'], 'summary.json')).read())
    assert s['today']['devices'] == 3 and 'salt' not in json.dumps(s)
    assert os.stat(os.path.join(os.environ['USAGE_DIR'], 'salt')).st_mode & 0o777 == 0o600


NEIGH = """192.168.1.100 dev br-lan lladdr 00:50:56:c0:00:01  ref 1 used 6/6/6probes 1 REACHABLE 
192.168.1.121 dev br-lan lladdr 00:0c:29:cb:82:64  used 267/267/233probes 1 STALE 
192.168.1.125 dev br-lan lladdr 00:0c:29:cb:82:64  used 734/613/575probes 1 STALE 
192.168.1.132 dev br-lan lladdr 00:0c:29:cb:82:64  used 4170/4170/4141probes 1 STALE 
192.168.0.8 dev eth1 lladdr 00:d7:6d:30:1d:4e  ref 1 used 5/0/5probes 4 REACHABLE 
192.168.1.55 dev br-lan  FAILED 
fe80::20c:29ff:fecb:8264 dev br-lan lladdr 00:0c:29:cb:82:64 STALE 
"""


def test_neighbor_ids(mod):
    nets = [__import__('ipaddress').ip_network('192.168.1.0/24')]
    ids = mod.neighbor_ids(NEIGH, {'br-lan'}, 'salt', nets)
    # .100 and one device with three aliases (same MAC, same segment); the old entry (4170 s) and the WAN neighbour are ignored
    assert len(ids) == 2


def test_one_mac_several_ips_is_one_device_but_routed_ips_are_separate(mod):
    nets = [__import__('ipaddress').ip_network('192.168.1.0/24')]
    a = mod.endpoint_id('192.168.1.121', 'aa:bb:cc:dd:ee:01', 's', nets)
    b = mod.endpoint_id('192.168.1.122', 'aa:bb:cc:dd:ee:01', 's', nets)
    assert a == b                                                   # same segment, same hardware address
    r1 = mod.endpoint_id('10.50.0.10', 'aa:bb:cc:dd:ee:99', 's', nets)
    r2 = mod.endpoint_id('10.50.0.11', 'aa:bb:cc:dd:ee:99', 's', nets)
    assert r1 != r2                                                 # routed in behind a router: counted by IP, not by the router's MAC


def test_read_flows_reads_every_page_when_the_daemon_is_not_there(mod, monkeypatch):
    pages = {1: {'flows': [{'n': 1}, {'n': 2}], 'last_page': 3}, 2: {'flows': [{'n': 3}], 'last_page': 3}, 3: {'flows': [{'n': 4}], 'last_page': 3}}
    calls = []

    def fake_run(cmd):
        arg = json.loads(cmd[-1])
        calls.append(arg)
        return json.dumps(pages[arg['page']])
    monkeypatch.setattr(mod, '_run', fake_run)
    monkeypatch.setattr(mod, 'FLOWS_URL', 'http://127.0.0.1:9/flows')       # nothing listens there
    monkeypatch.delenv('FLOWS_JSON', raising=False)
    assert [f['n'] for f in mod.read_flows()] == [1, 2, 3, 4]
    assert [c['page'] for c in calls] == [1, 2, 3] and all(c['per_page'] == mod.PAGE for c in calls)


def test_read_flows_prefers_the_daemon(mod, monkeypatch):
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({'flows': [{'n': i} for i in range(25)]}).encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(('127.0.0.1', 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(mod, 'FLOWS_URL', 'http://127.0.0.1:%d/flows' % srv.server_port)
    monkeypatch.setattr(mod, '_run', lambda cmd: (_ for _ in ()).throw(AssertionError('the pages must not be read')))
    monkeypatch.delenv('FLOWS_JSON', raising=False)
    assert len(mod.read_flows()) == 25
    srv.shutdown()
