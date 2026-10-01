import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from nethsec import license as lic

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


KEY = RSA.generate(2048)
OTHER_KEY = RSA.generate(2048)


def envelope(fields, key=KEY):
    payload = json.dumps(fields, sort_keys=True).encode()
    sig = pkcs1_15.new(key).sign(SHA256.new(payload))
    return {'payload': base64.b64encode(payload).decode(), 'signature': base64.b64encode(sig).decode(),
            'algorithm': 'RSA-SHA256'}


def write(tmp_path, signer=KEY, **fields):
    fields = {'hwid': 'abc', 'valid_until': (NOW + timedelta(days=14)).isoformat(), **fields}
    p = tmp_path / 'license.json'
    p.write_text(json.dumps(envelope(fields, signer)))
    return str(p)


def kw(tmp_path, license_file=None):
    pub = tmp_path / 'pubkey.pem'
    pub.write_bytes(KEY.publickey().export_key())
    return {'now': NOW, 'license_path': license_file or str(tmp_path / 'none.json'),
            'first_seen_path': str(tmp_path / 'first_seen'), 'pubkey_path': str(pub)}


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


def test_never_registered_gets_a_short_bootstrap_window(tmp_path):
    k = kw(tmp_path)
    assert lic.state(**k) == 'trial'                       # first sight recorded now
    assert lic.state(**dict(k, now=NOW + timedelta(hours=23))) == 'trial'
    assert lic.state(**dict(k, now=NOW + timedelta(hours=25))) == 'unlicensed'


def test_forged_license_is_rejected(tmp_path):
    f = write(tmp_path, signer=OTHER_KEY, status='active', license_state='subscribed',
              subscription_end=(NOW + timedelta(days=300)).isoformat())
    k = kw(tmp_path, f)
    assert lic.load(f, k['pubkey_path']) is None
    assert lic.state(**k) == 'unlicensed'
    assert lic.entitlements(**k)['security_services'] is False


def test_hand_edited_payload_is_rejected(tmp_path):
    f = write(tmp_path, status='expired', license_state='unlicensed')
    env = json.loads(open(f).read())
    forged = json.dumps({'hwid': 'abc', 'status': 'active', 'license_state': 'subscribed',
                         'valid_until': (NOW + timedelta(days=9)).isoformat(),
                         'subscription_end': (NOW + timedelta(days=99)).isoformat()}).encode()
    env['payload'] = base64.b64encode(forged).decode()
    open(f, 'w').write(json.dumps(env))
    assert lic.state(**kw(tmp_path, f)) == 'unlicensed'


def test_plain_json_and_garbage_are_unlicensed_not_bootstrap(tmp_path):
    f = tmp_path / 'license.json'
    f.write_text(json.dumps({'hwid': 'abc', 'status': 'active', 'license_state': 'subscribed'}))
    assert lic.state(**kw(tmp_path, str(f))) == 'unlicensed'
    f.write_text('not json')
    assert lic.state(**kw(tmp_path, str(f))) == 'unlicensed'


def test_missing_pubkey_fails_closed(tmp_path):
    f = write(tmp_path, status='active', license_state='subscribed',
              subscription_end=(NOW + timedelta(days=9)).isoformat())
    k = dict(kw(tmp_path, f), pubkey_path=str(tmp_path / 'nope.pem'))
    assert lic.state(**k) == 'unlicensed'


def test_lease_expiry_drops_to_unlicensed_even_if_subscription_runs(tmp_path):
    sub = (NOW + timedelta(days=200)).isoformat()
    f = write(tmp_path, status='active', license_state='subscribed', subscription_end=sub)
    assert lic.state(**kw(tmp_path, f)) == 'subscribed'
    late = dict(kw(tmp_path, f), now=NOW + timedelta(days=15))
    assert lic.state(**late) == 'unlicensed'


def test_license_without_lease_is_unlicensed(tmp_path):
    f = write(tmp_path, status='active', license_state='subscribed', valid_until=None,
              subscription_end=(NOW + timedelta(days=9)).isoformat())
    assert lic.state(**kw(tmp_path, f)) == 'unlicensed'


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
