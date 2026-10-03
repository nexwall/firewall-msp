import base64
import gzip
import hashlib
import importlib.machinery
import importlib.util
import json
import os

import pytest
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'files', 'nexwall-ips-rules')
VERSION = '2026.10.01.1'
KEY = RSA.generate(2048)
OTHER = RSA.generate(2048)


def rule(sid, action='block'):
    return '%s tcp any any -> any any ( msg:"r%d"; sid:%d; rev:1; )' % (action, sid, sid)


FILES = {
    'rules-connectivity.rules': [rule(1)],
    'rules-balanced.rules': [rule(1), rule(2), rule(3)],
    'rules-security.rules': [rule(1), rule(2), rule(3), rule(4)],
    'alerts.rules': [rule(2, 'alert'), rule(9, 'alert'), rule(10, 'alert')],
}


def make_manifest(key=KEY, tamper=None, kind='ips-signatures'):
    files, blobs = {}, {}
    for name, rules in FILES.items():
        raw = ('\n'.join(rules) + '\n').encode()
        data = gzip.compress(raw, 9, mtime=0)
        files[name + '.gz'] = {'name': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
                               'raw_sha256': hashlib.sha256(raw).hexdigest(), 'raw_size': len(raw)}
        blobs['/api/v1/ips/file/%s/%s.gz' % (VERSION, name)] = data
    if tamper:
        blobs['/api/v1/ips/file/%s/%s.gz' % (VERSION, tamper)] = gzip.compress(b'block tcp any any -> any any ( msg:"evil"; sid:666; )\n')
    payload = json.dumps({'kind': kind, 'version': VERSION, 'counts': {'tiers': {'balanced': 3}}, 'files': files}).encode()
    sig = pkcs1_15.new(key).sign(SHA256.new(payload))
    manifest = {'entitled': True, 'license_state': 'trial', 'bundle_version': VERSION,
                'payload': base64.b64encode(payload).decode(), 'signature': base64.b64encode(sig).decode()}
    return manifest, blobs


@pytest.fixture()
def env(tmp_path, monkeypatch):
    loader = importlib.machinery.SourceFileLoader('ips_rules', SCRIPT)
    spec = importlib.util.spec_from_loader('ips_rules', loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    (tmp_path / 'etc').mkdir()
    (tmp_path / 'cfg').mkdir()
    pub = tmp_path / 'pub.pem'
    pub.write_bytes(KEY.publickey().export_key())
    m.PUBKEY = str(pub)
    uci = {'snort.snort.ns_policy': 'balanced', 'snort.snort.config_dir': str(tmp_path / 'cfg'),
           'snort.snort.enabled': '0', 'snort.snort.ns_alert_excluded': '0'}
    monkeypatch.setattr(m, 'uci', lambda k, d='': uci.get(k, d))
    monkeypatch.setattr(m, 'cache_dir', lambda: str(tmp_path / 'cache'))
    monkeypatch.setattr(m, 'log', lambda msg: None)
    monkeypatch.setattr(m, 'disabled_sids', lambda: set())
    state = {'license': 'trial', 'manifest': make_manifest(), 'valid': True, 'calls': []}
    monkeypatch.setattr(m, 'license_state', lambda: state['license'])

    def fetch(path):
        state['calls'].append(path)
        manifest, blobs = state['manifest']
        if path == '/api/v1/ips/manifest':
            return json.dumps(manifest).encode()
        if path in blobs:
            return blobs[path]
        raise RuntimeError('404 ' + path)

    monkeypatch.setattr(m, 'fetch', fetch)
    monkeypatch.setattr(m, 'validate', lambda path: (state['valid'], '' if state['valid'] else 'ERROR: rejected'))
    m._env = {'uci': uci, 'state': state, 'tmp': tmp_path}
    return m


def installed(env):
    p = env._env['tmp'] / 'cfg' / 'rules' / 'snort.rules'
    return p.read_text() if p.exists() else None


def test_not_licensed_asks_nothing_and_signals_fallback(env):
    env._env['state']['license'] = 'unlicensed'
    assert env.cmd_update(force=True) == 3
    assert env._env['state']['calls'] == []


def test_update_downloads_and_verifies_the_chosen_tier(env):
    assert env.cmd_update(force=True) == 0
    st = env.load_state()
    assert st['version'] == VERSION and st['counts']['tiers']['balanced'] == 3
    assert os.path.exists(os.path.join(env.cache_dir(), VERSION, 'rules-balanced.rules'))
    assert not os.path.exists(os.path.join(env.cache_dir(), VERSION, 'rules-security.rules'))  # only what the policy needs


def test_manifest_signed_by_another_key_is_refused(env):
    env._env['state']['manifest'] = make_manifest(key=OTHER)
    assert env.cmd_update(force=True) == 1
    assert env.load_state().get('version') is None
    assert 'update failed' in env.load_state()['last_result']


def test_a_file_that_does_not_match_the_manifest_is_refused(env):
    env._env['state']['manifest'] = make_manifest(tamper='rules-balanced.rules')
    assert env.cmd_update(force=True) == 1
    assert env.load_state().get('version') is None


def test_wrong_kind_of_manifest_is_refused(env):
    env._env['state']['manifest'] = make_manifest(kind='dpi-catalog')
    assert env.cmd_update(force=True) == 1


def test_server_says_not_entitled_means_fallback(env):
    manifest, blobs = make_manifest()
    env._env['state']['manifest'] = ({'entitled': False, 'license_state': 'unlicensed'}, blobs)
    assert env.cmd_update(force=True) == 3


def test_apply_installs_the_policy_rules_and_reports_change_once(env, capsys):
    assert env.cmd_apply() == 0
    assert 'changed' in capsys.readouterr().out
    text = installed(env)
    assert text.startswith('# Nexwall IPS signatures %s, policy balanced' % VERSION)
    assert [l for l in text.splitlines() if l.startswith('block')] == FILES['rules-balanced.rules']
    assert env.cmd_apply() == 0
    assert 'changed' not in capsys.readouterr().out          # nothing new


def test_policy_change_fetches_the_other_tier(env):
    env.cmd_apply()
    env._env['uci']['snort.snort.ns_policy'] = 'security'
    assert env.cmd_apply() == 0
    assert any('sid:4' in l for l in installed(env).splitlines())


def test_alerts_exclude_what_the_policy_already_blocks_and_disabled_rules_go(env, monkeypatch):
    env._env['uci']['snort.snort.ns_alert_excluded'] = '1'
    monkeypatch.setattr(env, 'disabled_sids', lambda: {3})
    env.cmd_apply()
    lines = [l for l in installed(env).splitlines() if not l.startswith('#')]
    sids = sorted(int(env.SID_RE.search(l).group(1)) for l in lines)
    assert sids == [1, 2, 9, 10]                 # 2 blocks (not repeated as alert), 3 disabled, 9 and 10 alert only
    assert [l.split()[0] for l in lines if 'sid:9;' in l] == ['alert']


def test_rules_that_snort_rejects_never_replace_the_running_ones(env):
    env.cmd_apply()
    before = installed(env)
    env._env['state']['valid'] = False
    env._env['uci']['snort.snort.ns_policy'] = 'security'
    assert env.cmd_apply() == 1
    assert installed(env) == before
    assert 'rejected' in env.load_state()['last_result']
    assert not os.path.exists(os.path.join(str(env._env['tmp']), 'cfg', 'rules', 'snort.rules.new'))


def test_server_unreachable_keeps_using_the_cached_bundle(env):
    assert env.cmd_apply() == 0
    env._env['state']['manifest'] = ({}, {})            # every request now fails
    env._env['state']['calls'].clear()
    monkey_fail = lambda path: (_ for _ in ()).throw(RuntimeError('network down'))
    env.fetch = monkey_fail
    assert env.cmd_apply(download=True) == 0             # the cached rules are still good
    assert installed(env) is not None


def test_unlicensed_unit_always_falls_back_even_with_a_cache(env):
    env.cmd_apply()
    env._env['state']['license'] = 'unlicensed'
    assert env.cmd_apply(download=True) == 3


def test_license_service_not_answering_keeps_the_bundle_and_never_falls_back(env):
    assert env.cmd_apply() == 0
    before = installed(env)
    env._env['state']['license'] = 'unknown'
    assert env.cmd_apply(download=True) == 0             # keeps the verified cached bundle
    assert installed(env) == before
    assert 'not answering' in env.load_state()['last_result']


def test_license_service_not_answering_without_a_cache_asks_for_the_fallback(env):
    env._env['state']['license'] = 'unknown'
    assert env.cmd_apply() == 1                          # nothing cached: ns-snort-rules uses the Community rules
