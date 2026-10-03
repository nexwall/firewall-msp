import gzip
import hashlib
import importlib.machinery
import importlib.util
import json
import os

import pytest

SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'files', 'nexwall-threat-feeds')


@pytest.fixture()
def mod(tmp_path, monkeypatch):
    loader = importlib.machinery.SourceFileLoader('nexwall_threat_feeds', SCRIPT)
    spec = importlib.util.spec_from_loader('nexwall_threat_feeds', loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    monkeypatch.setattr(m, 'cache_dir', lambda: str(tmp_path / 'cache'))
    monkeypatch.setattr(m, 'log', lambda msg: None)
    return m


class Uci:
    """A fake uci: lists and values, records the changes."""
    def __init__(self, mod, monkeypatch, lists=None, values=None):
        self.lists, self.values, self.commands = dict(lists or {}), dict(values or {}), []
        monkeypatch.setattr(mod, 'uci_list', lambda key: list(self.lists.get(key, [])))
        monkeypatch.setattr(mod, 'uci', lambda key, default='': self.values.get(key, default))

        class R:
            returncode, stdout = 0, ''

        def fake_run(cmd, **kw):
            self.commands.append(cmd)
            if cmd[:2] == ['uci', 'add_list']:
                key, _, val = cmd[2].partition('=')
                self.lists.setdefault(key, []).append(val)
            elif cmd[:3] == ['uci', '-q', 'delete']:
                self.lists.pop(cmd[3], None)
            return R()

        monkeypatch.setattr(mod.subprocess, 'run', fake_run)


def make_manifest(version='2026.10.02.1'):
    files, cats = {}, {}
    for cid, kind, entries, default in (('malware', 'dns', ['evil.com', 'bad.net'], True), ('adult', 'dns', ['x.example.org'], False),
                                        ('attackers', 'ip', ['1.2.3.4', '5.6.7.0/24'], True)):
        raw = ('\n'.join(entries) + '\n').encode()
        data = gzip.compress(raw, mtime=0)
        name = '%s-%s.gz' % (kind, cid)
        files[name] = {'name': '%s-%s.txt' % (kind, cid), 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
                       'raw_sha256': hashlib.sha256(raw).hexdigest(), 'raw_size': len(raw), 'count': len(entries)}
        cats[cid] = {'kind': kind, 'title': cid.title(), 'description': 'd', 'default': default, 'count': len(entries), 'file': name}
    return {'version': version, 'kind': 'threat-feeds', 'categories': cats, 'files': files, 'counts': {c: v['count'] for c, v in cats.items()}}, \
        {n: gzip.compress(('\n'.join(['x']) + '\n').encode(), mtime=0) for n in files}


def test_size_class(mod):
    assert [mod.size_class(n) for n in (100, 20000, 99999, 100000, 399999, 400000, 799999, 800000)] == ['S', 'M', 'M', 'L', 'L', 'XL', 'XL', 'XXL']


def test_enabled_categories_follow_the_prefix_and_the_kind(mod, monkeypatch):
    Uci(mod, monkeypatch, lists={'adblock.global.adb_feed': ['nexwall_malware', 'adaway', 'nexwall_attackers'],
                                 'banip.global.ban_feed': ['nexwall_attackers', 'spamhaus', 'nexwall_malware']})
    manifest, _ = make_manifest()
    # a category counts only for its own kind: attackers is an address list, malware a domain list
    assert mod.enabled_categories(manifest) == {'malware', 'attackers'}


def test_legacy_choices_are_carried_over(mod, monkeypatch):
    u = Uci(mod, monkeypatch, lists={'adblock.global.adb_feed': ['adult', 'malware_privacy_lvl2', 'malware_privacy_lvl3', 'custom', 'nexwall_malware', 'gambling']})
    manifest, _ = make_manifest()           # has malware and adult, but no ads_tracking and no gambling
    assert mod.migrate_legacy(manifest) is True
    # no counterpart in the catalog: the dead entry is dropped
    assert u.lists['adblock.global.adb_feed'] == ['nexwall_adult', 'custom', 'nexwall_malware']
    assert ['uci', 'commit', 'adblock'] in u.commands
    assert mod.migrate_legacy(manifest) is False          # nothing left to migrate


def test_defaults_only_where_nothing_is_chosen(mod, monkeypatch):
    u = Uci(mod, monkeypatch)
    manifest, _ = make_manifest()
    monkeypatch.setattr(mod, 'total_memory_mib', lambda: 4096)
    assert mod.apply_defaults(manifest) is True
    # a unit with enough memory gets everything switched on
    assert sorted(u.lists['adblock.global.adb_feed']) == ['nexwall_adult', 'nexwall_malware']
    assert u.lists['banip.global.ban_feed'] == ['nexwall_attackers']
    u2 = Uci(mod, monkeypatch, lists={'adblock.global.adb_feed': ['nexwall_adult']})
    assert mod.apply_defaults(manifest) is True
    assert u2.lists['adblock.global.adb_feed'] == ['nexwall_adult']          # the administrator's choice stays
    assert u2.lists['banip.global.ban_feed'] == ['nexwall_attackers']


def test_a_small_unit_gets_only_the_default_categories(mod, monkeypatch):
    u = Uci(mod, monkeypatch)
    manifest, _ = make_manifest()
    manifest['categories']['adult']['count'] = 900000          # 70 MB of domains: too much for a 128 MiB unit
    monkeypatch.setattr(mod, 'total_memory_mib', lambda: 128)
    assert mod.apply_defaults(manifest) is True
    assert u.lists['adblock.global.adb_feed'] == ['nexwall_malware']
    assert u.lists['banip.global.ban_feed'] == ['nexwall_attackers']                  # address lists are small: always on


def test_download_checks_both_hashes_and_writes_plain_text(mod, monkeypatch):
    manifest, _ = make_manifest()
    data = gzip.compress(b'evil.com\nbad.net\n', mtime=0)
    manifest['files']['dns-malware.gz'].update(sha256=hashlib.sha256(data).hexdigest(), size=len(data),
                                               raw_sha256=hashlib.sha256(b'evil.com\nbad.net\n').hexdigest(), raw_size=17)
    monkeypatch.setattr(mod, 'fetch', lambda path: data)
    assert mod.download_category(manifest, 'malware') is True
    path = mod.category_path(manifest['version'], manifest, 'malware')
    assert open(path).read() == 'evil.com\nbad.net\n'
    assert mod.download_category(manifest, 'malware') is False           # already there
    os.remove(path)
    monkeypatch.setattr(mod, 'fetch', lambda path: data + b'x')           # tampered in transit
    with pytest.raises(ValueError):
        mod.download_category(manifest, 'malware')
    assert not os.path.exists(path)


def test_feeds_describe_every_category_as_a_local_file(mod, monkeypatch):
    Uci(mod, monkeypatch)
    manifest, _ = make_manifest()
    os.makedirs(mod.cache_dir())
    json.dump(manifest, open(os.path.join(mod.cache_dir(), 'manifest.json'), 'w'))
    mod.save_state({'version': manifest['version']})
    monkeypatch.setattr(mod, 'license_state', lambda: 'trial')
    monkeypatch.setattr(mod, 'ensure_files', lambda m: None)
    dns = mod.feeds('dns')
    assert set(dns) == {'nexwall_malware', 'nexwall_adult'}
    assert dns['nexwall_malware']['url'].startswith('file://') and dns['nexwall_malware']['url'].endswith('dns-malware.txt')
    assert dns['nexwall_malware']['rule'] == 'feed 1' and dns['nexwall_malware']['focus'] == 'Malware'
    ip = mod.feeds('ip')
    assert set(ip) == {'nexwall_attackers'} and 'url_4' in ip['nexwall_attackers'] and ip['nexwall_attackers']['chain'] == 'in'


@pytest.mark.parametrize('state,expected_empty', [('trial', False), ('subscribed', False), ('unknown', False), ('unlicensed', True)])
def test_feeds_need_the_license(mod, monkeypatch, state, expected_empty):
    Uci(mod, monkeypatch)
    manifest, _ = make_manifest()
    os.makedirs(mod.cache_dir())
    json.dump(manifest, open(os.path.join(mod.cache_dir(), 'manifest.json'), 'w'))
    mod.save_state({'version': manifest['version']})
    monkeypatch.setattr(mod, 'license_state', lambda: state)
    monkeypatch.setattr(mod, 'ensure_files', lambda m: None)
    assert (mod.feeds('dns') == {}) is expected_empty


def test_feeds_are_empty_while_the_catalog_and_the_state_disagree(mod, monkeypatch):
    Uci(mod, monkeypatch)
    manifest, _ = make_manifest()
    os.makedirs(mod.cache_dir())
    json.dump(manifest, open(os.path.join(mod.cache_dir(), 'manifest.json'), 'w'))
    mod.save_state({'version': '2000.01.01.1'})
    monkeypatch.setattr(mod, 'license_state', lambda: 'trial')
    assert mod.feeds('dns') == {}


def test_status_estimates_the_memory_of_the_enabled_domain_lists(mod, monkeypatch):
    Uci(mod, monkeypatch, lists={'adblock.global.adb_feed': ['nexwall_malware', 'nexwall_adult']})
    manifest, _ = make_manifest()
    manifest['categories']['malware']['count'] = 1_000_000
    os.makedirs(mod.cache_dir())
    json.dump(manifest, open(os.path.join(mod.cache_dir(), 'manifest.json'), 'w'))
    mod.save_state({'version': manifest['version']})
    monkeypatch.setattr(mod, 'license_state', lambda: 'trial')
    st = mod.installed_state()
    assert st['dns_memory_mib'] == round((1_000_000 + 1) * mod.BYTES_PER_DOMAIN / 1048576)
    assert {c['id']: c['enabled'] for c in st['categories']} == {'adult': True, 'attackers': False, 'malware': True}


def test_update_follows_the_license(mod, monkeypatch):
    Uci(mod, monkeypatch)
    monkeypatch.setattr(mod, 'license_state', lambda: 'unknown')
    assert mod.cmd_update() == 1
    monkeypatch.setattr(mod, 'license_state', lambda: 'unlicensed')
    assert mod.cmd_update() == 3
    assert 'not licensed' in mod.load_state()['last_result']


def test_update_downloads_the_enabled_categories_and_applies_defaults_once(mod, monkeypatch):
    u = Uci(mod, monkeypatch)
    manifest, _ = make_manifest()
    monkeypatch.setattr(mod, 'total_memory_mib', lambda: 4096)
    monkeypatch.setattr(mod, 'license_state', lambda: 'trial')
    monkeypatch.setattr(mod, 'fetch', lambda path: json.dumps({'entitled': True, 'payload': 'x', 'signature': 'y'}).encode())
    monkeypatch.setattr(mod, 'verify_manifest', lambda resp: manifest)
    got = []
    monkeypatch.setattr(mod, 'download_category', lambda m, cid: got.append(cid) or True)
    assert mod.cmd_update(force=True) == 0
    assert sorted(got) == ['adult', 'attackers', 'malware']                 # everything: the unit has the memory
    st = mod.load_state()
    assert st['version'] == manifest['version'] and st['changed'] is True and st['defaults_applied'] is True
    # a later update does not switch the defaults on again after the administrator removed them
    u.lists.clear()
    got.clear()
    assert mod.cmd_update(force=True) == 0
    assert got == [] and u.lists == {}


def test_update_with_a_bad_signature_keeps_what_is_there(mod, monkeypatch):
    Uci(mod, monkeypatch)
    monkeypatch.setattr(mod, 'license_state', lambda: 'trial')
    monkeypatch.setattr(mod, 'fetch', lambda path: json.dumps({'entitled': True, 'payload': 'x', 'signature': 'y'}).encode())

    def bad(resp):
        raise ValueError('bad signature')

    monkeypatch.setattr(mod, 'verify_manifest', bad)
    mod.save_state({'version': '2026.10.01.1', 'last_check': 0})
    assert mod.cmd_update(force=True) == 1
    st = mod.load_state()
    assert st['version'] == '2026.10.01.1' and 'bad signature' in st['last_error']


def test_sync_reloads_only_when_something_changed(mod, monkeypatch):
    Uci(mod, monkeypatch)
    calls = []
    monkeypatch.setattr(mod, 'reload_services', lambda d, i: calls.append((d, i)))
    monkeypatch.setattr(mod, 'cmd_update', lambda force=False: 0)
    mod.save_state({'version': 'v', 'changed': False, 'licensed': True})
    assert mod.cmd_sync() == 0 and calls == []
    mod.save_state({'version': 'v', 'changed': True, 'licensed': True})
    mod.cmd_sync()
    assert calls == [(True, True)] and mod.load_state()['changed'] is False
    # the license ends: the lists are taken away once, then nothing more
    monkeypatch.setattr(mod, 'cmd_update', lambda force=False: 3)
    calls.clear()
    mod.cmd_sync()
    mod.cmd_sync()
    assert calls == [(True, True)]
    # a failed update never reloads
    monkeypatch.setattr(mod, 'cmd_update', lambda force=False: 1)
    calls.clear()
    assert mod.cmd_sync() == 1 and calls == []
