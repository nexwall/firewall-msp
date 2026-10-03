import json
import os

import pytest

from test_threat_feeds import Uci, make_manifest, mod  # noqa: F401  (fixtures and helpers of the main test file)


def with_geo(manifest):
    for cid, fam in (('country_v4', 4), ('country_v6', 6)):
        name = 'geo-%s.gz' % cid
        manifest['files'][name] = {'name': 'geo-%s.txt' % cid, 'sha256': 'x', 'size': 1, 'raw_sha256': 'x', 'raw_size': 1, 'count': 1}
        manifest['categories'][cid] = {'kind': 'geo', 'title': cid, 'description': 'd', 'default': False, 'count': 3, 'file': name}
    return manifest


def install(mod, manifest):
    os.makedirs(mod.cache_dir(), exist_ok=True)
    json.dump(manifest, open(os.path.join(mod.cache_dir(), 'manifest.json'), 'w'))
    mod.save_state({'version': manifest['version']})
    os.makedirs(mod.version_dir(manifest['version']), exist_ok=True)


def write_geo_files(mod, manifest):
    for cid, text in (('country_v4', 'br 200.1.0.0/23\nbr 201.0.0.0/16\nus 8.8.8.0/23\n'), ('country_v6', 'br 2801:80::/29\nde 2001:db8::/32\n')):
        open(mod.category_path(manifest['version'], manifest, cid), 'w').write(text)


def test_the_country_lists_are_wanted_only_with_the_country_feed(mod, monkeypatch):
    manifest = with_geo(make_manifest()[0])
    Uci(mod, monkeypatch, lists={'banip.global.ban_feed': ['nexwall_attackers']})
    assert mod.enabled_categories(manifest) == {'attackers'}
    Uci(mod, monkeypatch, lists={'banip.global.ban_feed': ['nexwall_attackers', 'country']})
    assert mod.enabled_categories(manifest) == {'attackers', 'country_v4', 'country_v6'}


def test_per_country_files_are_what_banip_asks_for(mod, monkeypatch):
    manifest = with_geo(make_manifest()[0])
    install(mod, manifest)
    write_geo_files(mod, manifest)
    assert mod.prepare_geo(manifest) is True
    v4 = os.path.join(mod.geo_dir(manifest['version']), 'v4')
    v6 = os.path.join(mod.geo_dir(manifest['version']), 'v6')
    assert open(os.path.join(v4, 'br-aggregated.zone')).read() == '200.1.0.0/23\n201.0.0.0/16\n'
    assert open(os.path.join(v4, 'us-aggregated.zone')).read() == '8.8.8.0/23\n'
    assert open(os.path.join(v6, 'de-aggregated.zone')).read() == '2001:db8::/32\n'
    # a second run does nothing, a newer source file is split again
    mtime = os.path.getmtime(os.path.join(v4, 'br-aggregated.zone'))
    assert mod.prepare_geo(manifest) is True and os.path.getmtime(os.path.join(v4, 'br-aggregated.zone')) == mtime
    src = mod.category_path(manifest['version'], manifest, 'country_v4')
    open(src, 'w').write('br 202.0.0.0/16\n')
    os.utime(src, (mtime + 100, mtime + 100))
    assert mod.prepare_geo(manifest) is True
    assert open(os.path.join(v4, 'br-aggregated.zone')).read() == '202.0.0.0/16\n' and not os.path.exists(os.path.join(v4, 'us-aggregated.zone'))


def test_not_ready_while_a_family_is_missing(mod):
    manifest = with_geo(make_manifest()[0])
    install(mod, manifest)
    assert mod.prepare_geo(manifest) is False


def test_geo_blocking_uses_our_files_when_licensed(mod, monkeypatch):
    manifest = with_geo(make_manifest()[0])
    install(mod, manifest)
    write_geo_files(mod, manifest)
    Uci(mod, monkeypatch, lists={'banip.global.ban_feed': ['country']})
    monkeypatch.setattr(mod, 'ensure_files', lambda m: None)
    monkeypatch.setattr(mod, 'license_state', lambda: 'trial')
    ip = mod.feeds('ip')
    country = ip['country']
    assert country['url_4'].startswith('file://') and country['url_4'].endswith('/geo/v4/') and country['url_6'].endswith('/geo/v6/')
    assert country['rule'] == 'feed 1' and country['chain'] == 'in'
    # geo-blocking off: no override, banIP is left alone
    Uci(mod, monkeypatch, lists={'banip.global.ban_feed': ['nexwall_attackers']})
    assert 'country' not in mod.feeds('ip')


@pytest.mark.parametrize('state', ['unlicensed'])
def test_no_country_lists_without_a_license(mod, monkeypatch, state):
    manifest = with_geo(make_manifest()[0])
    install(mod, manifest)
    write_geo_files(mod, manifest)
    Uci(mod, monkeypatch, lists={'banip.global.ban_feed': ['country']})
    monkeypatch.setattr(mod, 'license_state', lambda: state)
    assert mod.feeds('ip') == {}
