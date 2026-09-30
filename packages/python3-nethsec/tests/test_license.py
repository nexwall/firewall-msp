import json
from datetime import datetime, timedelta, timezone

import pytest

from nethsec import license as lic

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


def write(tmp_path, **fields):
    p = tmp_path / 'license.json'
    p.write_text(json.dumps({'hwid': 'abc', **fields}))
    return str(p)


def kw(tmp_path, license_file=None):
    return {'now': NOW, 'license_path': license_file or str(tmp_path / 'none.json'),
            'first_seen_path': str(tmp_path / 'first_seen')}


def test_subscribed_is_full(tmp_path):
    f = write(tmp_path, status='active', license_state='subscribed',
              subscription_end=(NOW + timedelta(days=5)).isoformat())
    assert lic.state(**kw(tmp_path, f)) == 'subscribed'
    e = lic.entitlements(**kw(tmp_path, f))
    assert e['security_services'] and e['reverse_proxy'] and e['ha'] and e['limits']['ipsec_s2s'] is None


def test_subscription_ended_offline_drops_to_unlicensed(tmp_path):
    f = write(tmp_path, status='active', license_state='subscribed',
              subscription_end=(NOW - timedelta(days=1)).isoformat())
    assert lic.state(**kw(tmp_path, f)) == 'unlicensed'


def test_trial_is_full_until_it_ends(tmp_path):
    f = write(tmp_path, status='unassigned', license_state='trial', trial_end=(NOW + timedelta(days=3)).isoformat())
    assert lic.state(**kw(tmp_path, f)) == 'trial'
    assert lic.entitlements(**kw(tmp_path, f))['security_services'] is True
    f = write(tmp_path, status='unassigned', license_state='trial', trial_end=(NOW - timedelta(seconds=1)).isoformat())
    assert lic.state(**kw(tmp_path, f)) == 'unlicensed'


def test_unlicensed_limits(tmp_path):
    f = write(tmp_path, status='expired', license_state='unlicensed')
    e = lic.entitlements(**kw(tmp_path, f))
    assert e['security_services'] is False and e['reverse_proxy'] is False and e['ha'] is False
    assert e['limits'] == {'ipsec_s2s': 1, 'wireguard': 1, 'sslvpn_users': 3}


def test_never_registered_gets_a_local_30_day_trial_from_first_sight(tmp_path):
    k = kw(tmp_path)
    assert lic.state(**k) == 'trial'                       # first sight recorded now
    later = dict(k, now=NOW + timedelta(days=29))
    assert lic.state(**later) == 'trial'
    later = dict(k, now=NOW + timedelta(days=31))
    assert lic.state(**later) == 'unlicensed'


def test_feature_and_limit_errors(tmp_path):
    f = write(tmp_path, status='expired', license_state='unlicensed')
    k = kw(tmp_path, f)
    assert lic.feature_error('ha', **k)['validation']['errors'][0]['message'] == 'license_required'
    assert lic.limit_error('ipsec_s2s', 0, **k) is None
    err = lic.limit_error('ipsec_s2s', 1, **k)
    assert err['validation']['errors'][0]['message'] == 'license_limit_reached'
    assert lic.limit_error('sslvpn_users', 2, **k) is None and lic.limit_error('sslvpn_users', 3, **k)
    full = write(tmp_path, status='active', license_state='subscribed', subscription_end=(NOW + timedelta(days=9)).isoformat())
    kf = kw(tmp_path, full)
    assert lic.feature_error('ha', **kf) is None and lic.limit_error('ipsec_s2s', 50, **kf) is None


def test_server_can_tighten_a_subscription(tmp_path):
    f = write(tmp_path, status='active', license_state='subscribed',
              subscription_end=(NOW + timedelta(days=9)).isoformat(),
              entitlements={'ha': False, 'limits': {'wireguard': 5}})
    e = lic.entitlements(**kw(tmp_path, f))
    assert e['ha'] is False and e['limits']['wireguard'] == 5 and e['security_services'] is True
