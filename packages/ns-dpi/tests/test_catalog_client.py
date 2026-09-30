import base64, hashlib, importlib.machinery, importlib.util, json, os, time
import pytest
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'files', 'nexwall-dpi-catalog')

APPS = ''.join('app:%d:netify.a%d\n' % (i, i) for i in range(1, 130)) + 'ver:nexwall-2026.09.30.1\ndom:5:example.com\n'
CATS = json.dumps({'application_index': [], 'application_tag_index': {}, 'protocol_index': [], 'protocol_tag_index': {}})
OPEN_APPS = ''.join('app:%d:netify.o%d\n' % (i, i) for i in range(1, 110))


class Resp:
    def __init__(self, status=200, body=None, content=b''):
        self.status_code, self._body, self.content = status, body, content

    def json(self):
        return self._body


@pytest.fixture()
def env(tmp_path, monkeypatch):
    loader = importlib.machinery.SourceFileLoader('catalog_client', SCRIPT)
    spec = importlib.util.spec_from_loader('catalog_client', loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    d = tmp_path
    for sub in ('etc/netifyd', 'usr/share/netifyd', 'lic'):
        (d / sub).mkdir(parents=True)
    m.STATE_DIR = str(d / 'etc/netifyd/catalog')
    m.STATE_FILE = m.STATE_DIR + '/state.json'
    m.LOCK_FILE = str(d / 'lock')
    m.LIVE = {'netify-apps.conf': str(d / 'etc/netifyd/netify-apps.conf'), 'netify-categories.json': str(d / 'etc/netifyd/netify-categories.json')}
    m.OPEN = {'netify-apps.conf': str(d / 'usr/share/netifyd/netify-apps.conf'), 'netify-categories.json': str(d / 'usr/share/netifyd/netify-categories.json')}
    m.LICENSE_DIR = str(d / 'lic')
    (d / 'usr/share/netifyd/netify-apps.conf').write_text(OPEN_APPS)
    (d / 'usr/share/netifyd/netify-categories.json').write_text(CATS)
    (d / 'etc/netifyd/netify-apps.conf').write_text(OPEN_APPS)
    (d / 'etc/netifyd/netify-categories.json').write_text(CATS)
    key = RSA.generate(2048)
    (d / 'lic/pubkey.pem').write_bytes(key.publickey().export_key())
    (d / 'lic/hwid').write_text('a1b2c3d4e5f6\n')
    (d / 'lic/device_token').write_text('tok\n')
    m._key = key
    m._reloads = []
    m._alive = True
    m._state = 'trial'
    m._uci = {}
    monkeypatch.setattr(m, 'reload_engine', lambda: (m._reloads.append(1), m._alive)[1])
    monkeypatch.setattr(m, 'license_state', lambda: m._state)
    monkeypatch.setattr(m, 'uci', lambda k, default='': m._uci.get(k, default))
    monkeypatch.setattr(m, 'log', lambda msg, level='info': None)
    m._server = {'entitled': True, 'files': {'netify-apps.conf': APPS.encode(), 'netify-categories.json': CATS.encode()}}
    monkeypatch.setattr(m.requests, 'get', lambda url, headers=None, timeout=None: serve(m, url, headers))
    return m, d


def sign(m, manifest, tamper=False):
    payload = json.dumps(manifest, sort_keys=True).encode()
    sig = pkcs1_15.new(m._key).sign(SHA256.new(payload))
    if tamper:
        payload = payload.replace(b'2026', b'2027')
    return {'payload': base64.b64encode(payload).decode(), 'signature': base64.b64encode(sig).decode()}


def serve(m, url, headers):
    assert headers['X-Nexwall-HWID'] == 'a1b2c3d4e5f6' and headers['X-Nexwall-Token'] == 'tok'
    s = m._server
    if url.endswith('/api/v1/dpi/manifest'):
        if not s['entitled']:
            return Resp(200, {'entitled': False, 'license_state': 'unlicensed'})
        files = {n: {'sha256': hashlib.sha256(b).hexdigest(), 'size': len(b)} for n, b in s['files'].items()}
        manifest = {'kind': 'dpi-catalog', 'version': '2026.09.30.1', 'files': files,
                    'counts': {'applications': 129, 'domains': 1, 'networks': 0}}
        j = {'entitled': True, 'license_state': m._state, 'catalog_version': '2026.09.30.1'}
        j.update(sign(m, manifest, s.get('tamper_manifest', False)))
        return Resp(200, j)
    name = url.rsplit('/', 1)[1]
    return Resp(200, None, s['files'][name])


def state(d):
    return json.load(open(d / 'etc/netifyd/catalog/state.json'))


def test_licensed_unit_installs_the_catalog(env):
    m, d = env
    assert m.run('update') == 0
    assert (d / 'etc/netifyd/netify-apps.conf').read_text() == APPS
    s = state(d)
    assert s['installed_version'] == '2026.09.30.1' and s['source'] == 'nexwall' and s['last_error'] is None
    assert m._reloads


def test_second_update_is_a_noop_when_up_to_date(env):
    m, d = env
    m.run('update'); m._reloads.clear()
    m.run('sync')  # interval not due
    assert not m._reloads
    m._state = 'trial'; m.run('update')  # forced check, same version
    # forced update reinstalls only when the version differs or on explicit force
    assert state(d)['installed_version'] == '2026.09.30.1'


def test_tampered_file_is_rejected_and_nothing_changes(env):
    m, d = env
    m._server['tamper_files'] = True
    orig = m._server['files']['netify-apps.conf']
    real_get = m.requests.get

    def get(url, headers=None, timeout=None):
        r = real_get(url, headers=headers, timeout=timeout)
        if url.endswith('netify-apps.conf'):
            r.content = orig + b'dom:1:evil.example\n'
        return r
    m.requests.get = get
    assert m.run('update') == 1
    assert (d / 'etc/netifyd/netify-apps.conf').read_text() == OPEN_APPS
    assert 'signed manifest' in state(d)['last_error']


def test_bad_signature_is_rejected(env):
    m, d = env
    m._server['tamper_manifest'] = True
    assert m.run('update') == 1
    assert (d / 'etc/netifyd/netify-apps.conf').read_text() == OPEN_APPS
    assert state(d)['installed_version'] is None if 'installed_version' in state(d) else True


def test_invalid_rule_file_is_rejected(env):
    m, d = env
    m._server['files']['netify-apps.conf'] = (APPS + 'evil:1:x\n').encode()
    assert m.run('update') == 1
    assert (d / 'etc/netifyd/netify-apps.conf').read_text() == OPEN_APPS
    assert 'unknown rule type' in state(d)['last_error']


def test_too_small_rule_file_is_rejected(env):
    m, d = env
    m._server['files']['netify-apps.conf'] = b'app:1:netify.a\n'
    assert m.run('update') == 1
    assert 'only 1 applications' in state(d)['last_error']


def test_engine_that_dies_after_reload_rolls_back(env):
    m, d = env
    m._alive = False
    assert m.run('update') == 1
    assert (d / 'etc/netifyd/netify-apps.conf').read_text() == OPEN_APPS
    assert 'not running' in state(d)['last_error']


def test_unlicensed_unit_returns_to_the_open_list(env):
    m, d = env
    m.run('update')
    assert (d / 'etc/netifyd/netify-apps.conf').read_text() == APPS
    m._state = 'unlicensed'
    m.run('sync')  # a lapsed license is enforced at once, regardless of the interval
    assert (d / 'etc/netifyd/netify-apps.conf').read_text() == OPEN_APPS
    s = state(d)
    assert s['source'] == 'open' and s['installed_version'] is None and 'license unlicensed' in s['last_result']


def test_server_says_not_entitled_returns_to_the_open_list(env):
    m, d = env
    m.run('update')
    m._server['entitled'] = False
    m.run('update')
    assert (d / 'etc/netifyd/netify-apps.conf').read_text() == OPEN_APPS


def test_relicensed_unit_gets_the_catalog_again_by_sync(env):
    m, d = env
    m.run('update')
    m._state = 'unlicensed'; m.run('sync')
    m._state = 'subscribed'
    m.run('sync')  # nothing installed and entitled: installs at once
    assert (d / 'etc/netifyd/netify-apps.conf').read_text() == APPS


def test_auto_update_off_does_nothing_by_itself_but_update_works(env):
    m, d = env
    m._uci['dpi.catalog.auto_update'] = '0'
    m.run('sync')
    assert (d / 'etc/netifyd/netify-apps.conf').read_text() == OPEN_APPS
    m.run('update')
    assert (d / 'etc/netifyd/netify-apps.conf').read_text() == APPS


def test_interval_controls_when_a_sync_checks(env):
    m, d = env
    m.run('update')
    s = state(d); s['last_check'] = int(time.time()) - 3600; json.dump(s, open(m.STATE_FILE, 'w'))
    m._uci['dpi.catalog.interval'] = '24'
    calls = []
    real = m.requests.get
    m.requests.get = lambda *a, **k: (calls.append(a[0]), real(*a, **k))[1]
    m.run('sync'); assert not calls          # 1 h ago, interval 24 h
    m._uci['dpi.catalog.interval'] = '1'
    m.run('sync'); assert calls              # due now


def test_unregistered_unit_waits(env):
    m, d = env
    os.remove(d / 'lic/device_token')
    assert m.run('update') == 0
    assert state(d)['last_result'] == 'waiting for registration'
    assert (d / 'etc/netifyd/netify-apps.conf').read_text() == OPEN_APPS


def test_a_firmware_upgrade_that_restored_the_open_list_is_repaired_by_sync(env):
    m, d = env
    m.run('update')
    (d / 'etc/netifyd/netify-apps.conf').write_text(OPEN_APPS)  # what the upgrade does
    m._reloads.clear()
    m.run('sync')  # state still says installed, the live file disagrees
    assert (d / 'etc/netifyd/netify-apps.conf').read_text() == APPS
