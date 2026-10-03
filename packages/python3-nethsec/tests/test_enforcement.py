import json

import pytest

from nethsec.license.enforcement import dpi_enforcement, ips_enforcement

NOW = 1_790_000_000


@pytest.fixture()
def paths(tmp_path):
    plugin = tmp_path / 'libnx-proc-flow-actions.so'
    plugin.write_text('x')
    return {'stats_path': str(tmp_path / 'stats.json'), 'plugin_path': str(plugin), 'now': NOW, 'core': 'up'}


def stats(paths, **fields):
    with open(paths['stats_path'], 'w') as f:
        json.dump({'updated': NOW - 5, 'license': 'valid', **fields}, f)


def test_active_when_licensed_and_plugin_reports_a_valid_token(paths):
    stats(paths)
    r = dpi_enforcement(state='subscribed', security_services=True, **paths)
    assert r == {'active': True, 'cause': None, 'reason': 'valid', 'license_state': 'subscribed'}


def test_trial_counts_as_licensed(paths):
    stats(paths)
    assert dpi_enforcement(state='trial', security_services=True, **paths)['active'] is True


def test_suspended_by_license_when_unlicensed_or_plan_lacks_it(paths):
    stats(paths, license='no token')
    assert dpi_enforcement(state='unlicensed', security_services=False, **paths)['cause'] == 'license'
    assert dpi_enforcement(state='subscribed', security_services=False, **paths)['cause'] == 'license'


def test_licensed_but_plugin_has_no_token_means_the_license_service_is_down(paths):
    for reason in ('no token', 'expired', 'bad signature'):
        stats(paths, license=reason)
        r = dpi_enforcement(state='subscribed', security_services=True, **paths)
        assert r['active'] is False and r['cause'] == 'service' and r['reason'] == reason


def test_stale_or_missing_stats_mean_the_engine_is_not_reporting(paths):
    r = dpi_enforcement(state='subscribed', security_services=True, **paths)  # no file yet
    assert r['cause'] == 'engine'
    stats(paths, updated=NOW - 300)
    assert dpi_enforcement(state='subscribed', security_services=True, **paths)['cause'] == 'engine'


def test_missing_plugin_is_reported_as_community_build(paths, tmp_path):
    stats(paths)
    paths['plugin_path'] = str(tmp_path / 'not-installed.so')
    assert dpi_enforcement(state='subscribed', security_services=True, **paths)['cause'] == 'plugin'


def test_garbage_stats_file_is_not_a_crash(paths):
    with open(paths['stats_path'], 'w') as f:
        f.write('not json')
    assert dpi_enforcement(state='subscribed', security_services=True, **paths)['cause'] == 'engine'


def test_installed_license_service_that_does_not_answer_is_the_cause(paths):
    stats(paths, license='no token')
    paths['core'] = 'down'
    # even though every license question would read "unlicensed" without the core
    r = dpi_enforcement(state='unlicensed', security_services=False, **paths)
    assert r['active'] is False and r['cause'] == 'service'


def test_community_build_without_a_core_reads_the_license_normally(paths):
    stats(paths, license='no token')
    paths['core'] = 'absent'
    assert dpi_enforcement(state='unlicensed', security_services=False, **paths)['cause'] == 'license'


@pytest.fixture()
def ips(tmp_path):
    gate = tmp_path / 'nx_ips_gate.so'
    gate.write_text('x')
    token = tmp_path / 'token'
    token.write_text('t')
    return {'gate_path': str(gate), 'token_path': str(token), 'enabled': True, 'core': 'up', 'running': True,
            'state': 'subscribed', 'security_services': True}


def test_ips_active_when_licensed_gated_and_running(ips):
    r = ips_enforcement(**ips)
    assert r['applicable'] and r['active'] and r['cause'] is None


def test_ips_not_applicable_while_switched_off(ips):
    ips['enabled'] = False
    r = ips_enforcement(**ips)
    assert r['applicable'] is False and r['active'] is False


def test_ips_causes(ips):
    assert ips_enforcement(**dict(ips, core='down'))['cause'] == 'service'
    assert ips_enforcement(**dict(ips, state='unlicensed', security_services=False))['cause'] == 'license'
    assert ips_enforcement(**dict(ips, gate_path=ips['gate_path'] + '.gone'))['cause'] == 'plugin'
    assert ips_enforcement(**dict(ips, token_path=ips['token_path'] + '.gone'))['cause'] == 'service'
    assert ips_enforcement(**dict(ips, running=False))['cause'] == 'engine'
