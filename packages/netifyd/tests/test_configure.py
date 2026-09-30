import importlib.machinery, importlib.util, os, sys, types
import pytest

SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'files', 'ns-netifyd-configure')

ORIGINAL = """# NethSecurity default configuration

[capture-interface-lan]
capture_type = nfqueue
role = lan
queue_id = 50
queue_instances = 4
conntrack_counters = true

[capture-interface-wan]
capture_type = nfqueue
role = wan
queue_id = 54
queue_instances = 4
conntrack_counters = true

# vim: set ft=dosini :
"""


@pytest.fixture()
def mod():
    # the functions under test need neither library: stub the imports so the script loads anywhere
    euci = types.ModuleType('euci'); euci.EUci = object
    jinja = types.ModuleType('jinja2'); jinja.Environment = object; jinja.BaseLoader = object
    saved = {k: sys.modules.get(k) for k in ('euci', 'jinja2')}
    sys.modules['euci'] = euci; sys.modules['jinja2'] = jinja
    loader = importlib.machinery.SourceFileLoader('ns_netifyd_configure', SCRIPT)
    spec = importlib.util.spec_from_loader('ns_netifyd_configure', loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    yield m
    for k, v in saved.items():
        if v is None: sys.modules.pop(k, None)
        else: sys.modules[k] = v


class FakeUci:
    def __init__(self, values): self.values = values
    def get(self, config, section, option, default=None): return self.values.get(option, default)


def sections(text):
    out, cur = {}, None
    for line in text.split('\n'):
        s = line.strip()
        if s.startswith('[') and s.endswith(']'):
            cur = s[1:-1]; out[cur] = {}
        elif cur and '=' in s and not s.startswith('#'):
            k, v = s.split('=', 1); out[cur][k.strip()] = v.strip()
    return out


def test_policy_defaults_to_allow_and_256(mod):
    assert mod.read_engine_policy(FakeUci({})) == (False, 256)


@pytest.mark.parametrize('values,expected', [
    ({'overload_action': 'block', 'queue_limit': '512'}, (True, 512)),
    ({'overload_action': 'BLOCK'}, (True, 256)),
    ({'overload_action': 'allow', 'queue_limit': '128'}, (False, 128)),
    ({'overload_action': 'nonsense'}, (False, 256)),
    ({'queue_limit': '999'}, (False, 256)),
    ({'queue_limit': 'abc'}, (False, 256)),
    ({'queue_limit': '1024'}, (False, 1024)),
])
def test_policy_values_and_fallbacks(mod, values, expected):
    assert mod.read_engine_policy(FakeUci(values)) == expected


def test_policy_adds_missing_keys(mod, tmp_path):
    f = tmp_path / '10-nfqueue.conf'; f.write_text(ORIGINAL)
    assert mod.apply_queue_policy(False, 256, str(f)) is True
    s = sections(f.read_text())
    assert s['capture-interface-lan']['queue_maxlen'] == '256' and s['capture-interface-lan']['queue_fail_open'] == 'yes'
    assert s['capture-interface-wan']['queue_maxlen'] == '256' and s['capture-interface-wan']['queue_fail_open'] == 'yes'
    assert s['capture-interface-lan']['queue_instances'] == '4'          # other keys kept
    assert '# vim: set ft=dosini :' in f.read_text()


def test_block_only_changes_the_forward_queues(mod, tmp_path):
    f = tmp_path / 'q.conf'; f.write_text(ORIGINAL)
    mod.apply_queue_policy(True, 512, str(f))
    s = sections(f.read_text())
    assert s['capture-interface-lan']['queue_fail_open'] == 'no'          # LAN traffic: block
    assert s['capture-interface-wan']['queue_fail_open'] == 'yes'         # the firewall's own traffic always passes
    assert s['capture-interface-lan']['queue_maxlen'] == s['capture-interface-wan']['queue_maxlen'] == '512'


def test_policy_is_idempotent_and_reversible(mod, tmp_path):
    f = tmp_path / 'q.conf'; f.write_text(ORIGINAL)
    mod.apply_queue_policy(True, 128, str(f))
    assert mod.apply_queue_policy(True, 128, str(f)) is False            # nothing to do, engine not reloaded
    assert mod.apply_queue_policy(False, 256, str(f)) is True
    s = sections(f.read_text())
    assert s['capture-interface-lan']['queue_fail_open'] == 'yes' and s['capture-interface-lan']['queue_maxlen'] == '256'
    # no duplicate keys after several rounds
    assert f.read_text().count('queue_fail_open') == 2 and f.read_text().count('queue_maxlen') == 2


def test_missing_interface_file_is_not_an_error(mod, tmp_path):
    assert mod.apply_queue_policy(False, 256, str(tmp_path / 'nope.conf')) is False
