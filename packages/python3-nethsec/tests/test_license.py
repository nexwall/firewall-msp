import json
import socket
import threading

import pytest

from nethsec import license as lic


@pytest.fixture()
def core(tmp_path, monkeypatch):
    """A fake license core on a unix socket; `answers` maps command -> reply, `calls` records requests."""
    path = str(tmp_path / 'lic.sock')
    monkeypatch.setattr(lic, 'DAEMON_SOCKET', path)
    monkeypatch.setattr(lic, 'CORE_BINARY', str(tmp_path / 'not-installed'))
    state = {'answers': {}, 'calls': []}
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(8)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            req = json.loads(conn.recv(4096))
            state['calls'].append(req['cmd'])
            conn.sendall(json.dumps(state['answers'].get(req['cmd'], {'ok': False})).encode())
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    yield state
    srv.close()


def test_answers_come_from_the_core(core):
    core['answers'] = {
        'state': {'ok': True, 'state': 'subscribed'},
        'entitlements': {'ok': True, 'state': 'subscribed', 'entitlements': lic.FULL},
        'payload': {'ok': True, 'payload': {'hwid': 'x', 'partner_name': 'Acme'}},
    }
    assert lic.state() == 'subscribed'
    e = lic.entitlements()
    assert e['security_services'] and e['reverse_proxy'] and e['ha'] and e['limits']['ipsec_s2s'] is None
    assert lic.load()['partner_name'] == 'Acme'
    assert lic.feature_error('ha') is None and lic.limit_error('ipsec_s2s', 50) is None


def test_no_core_means_unlicensed_and_limited(tmp_path, monkeypatch):
    monkeypatch.setattr(lic, 'DAEMON_SOCKET', str(tmp_path / 'missing.sock'))
    monkeypatch.setattr(lic, 'CORE_BINARY', str(tmp_path / 'not-installed'))
    assert lic.state() == 'unlicensed' and lic.load() is None
    e = lic.entitlements()
    assert e['security_services'] is False and e['reverse_proxy'] is False and e['ha'] is False
    assert e['limits'] == {'ipsec_s2s': 1, 'wireguard': 1, 'sslvpn_users': 3}


def test_a_file_on_disk_is_never_consulted(tmp_path, monkeypatch):
    # an edited or forged license file changes nothing: the module has no local evaluation at all
    monkeypatch.setattr(lic, 'DAEMON_SOCKET', str(tmp_path / 'missing.sock'))
    monkeypatch.setattr(lic, 'CORE_BINARY', str(tmp_path / 'not-installed'))
    f = tmp_path / 'license.json'
    f.write_text(json.dumps({'hwid': 'x', 'status': 'active', 'license_state': 'subscribed'}))
    assert lic.state(license_path=str(f)) == 'unlicensed'
    assert lic.entitlements(license_path=str(f))['ha'] is False


def test_refused_answer_falls_back_to_limited(core):
    core['answers'] = {'state': {'ok': False}, 'entitlements': {'ok': False}}
    assert lic.state() == 'unlicensed'
    assert lic.entitlements()['security_services'] is False


def test_feature_and_limit_errors(core):
    core['answers'] = {'entitlements': {'ok': True, 'entitlements': lic.LIMITED}}
    assert lic.feature_error('ha')['validation']['errors'][0]['message'] == 'license_required'
    assert lic.limit_error('ipsec_s2s', 0) is None
    err = lic.limit_error('ipsec_s2s', 1)
    assert err['validation']['errors'][0]['message'] == 'license_limit_reached'
    assert lic.limit_error('sslvpn_users', 2) is None and lic.limit_error('sslvpn_users', 3)
    assert lic.limit('wireguard') == 1


def test_server_can_tighten_a_subscription(core):
    ent = json.loads(json.dumps(lic.FULL))
    ent['ha'] = False
    ent['limits']['wireguard'] = 5
    core['answers'] = {'entitlements': {'ok': True, 'entitlements': ent}}
    e = lic.entitlements()
    assert e['ha'] is False and e['limits']['wireguard'] == 5 and e['security_services'] is True


def test_require_raises_the_api_error(core):
    core['answers'] = {'entitlements': {'ok': True, 'entitlements': lic.LIMITED}}
    with pytest.raises(lic.utils.ValidationError):
        lic.require('reverse_proxy')


def test_installed_core_that_is_restarting_is_waited_for(tmp_path, monkeypatch):
    monkeypatch.setattr(lic, 'DAEMON_SOCKET', str(tmp_path / 'late.sock'))
    binary = tmp_path / 'installed'
    binary.write_text('x')
    monkeypatch.setattr(lic, 'CORE_BINARY', str(binary))
    monkeypatch.setattr(lic.time, 'sleep', lambda s: None)
    tries = []
    real = lic._ask_once

    def flaky(req):
        tries.append(1)
        return real(req) if len(tries) < 3 else {'ok': True, 'state': 'trial'}

    monkeypatch.setattr(lic, '_ask_once', flaky)
    assert lic.state() == 'trial' and len(tries) == 3
