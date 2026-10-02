import pytest
from euci import EUci

from nethsec import performance
from nethsec.utils import ValidationError


@pytest.fixture
def e_uci(tmp_path):
    (tmp_path / 'dpi').write_text('')
    (tmp_path / 'nexwall_perf').write_text('')
    (tmp_path / 'network').write_text("config interface 'lan'\n\toption proto 'static'\n")
    return EUci(confdir=str(tmp_path))


def test_defaults(e_uci, mocker):
    mocker.patch.object(performance, 'cpu_count', return_value=4)
    assert performance.get_settings(e_uci) == {
        'dpi_threads': 'auto', 'dpi_threads_auto': 2, 'fastpath': False, 'packet_steering': False, 'ring_buffers': False, 'cpu_count': 4}


@pytest.mark.parametrize('cores,expected', [(1, 1), (2, 1), (3, 1), (4, 2), (7, 3), (8, 4), (64, 4)])
def test_auto_threads(cores, expected):
    assert performance.auto_dpi_threads(cores) == expected


def test_store_and_read_back(e_uci, mocker):
    mocker.patch.object(performance, 'cpu_count', return_value=8)
    performance.set_settings(e_uci, dpi_threads='3', fastpath=True, packet_steering=True)
    got = performance.get_settings(e_uci)
    assert got['dpi_threads'] == '3' and got['fastpath'] is True and got['packet_steering'] is True
    performance.set_settings(e_uci, fastpath=False)
    got = performance.get_settings(e_uci)
    assert got['fastpath'] is False and got['dpi_threads'] == '3' and got['packet_steering'] is True


def test_steering_reuses_the_existing_globals_section(e_uci):
    e_uci.set('network', 'globals', 'globals')
    e_uci.set('network', 'globals', 'ula_prefix', 'fd00::/48')
    e_uci.save('network')
    performance.set_settings(e_uci, packet_steering=True)
    assert e_uci.get('network', 'globals', 'packet_steering') == '1'
    assert e_uci.get('network', 'globals', 'ula_prefix') == 'fd00::/48'


@pytest.mark.parametrize('kwargs,parameter', [
    ({'dpi_threads': '9'}, 'dpi_threads'), ({'dpi_threads': 'x'}, 'dpi_threads'),
    ({'fastpath': 1}, 'fastpath'), ({'fastpath': 'yes'}, 'fastpath'), ({'packet_steering': 'on'}, 'packet_steering'),
])
def test_bad_values_change_nothing(e_uci, kwargs, parameter):
    with pytest.raises(ValidationError) as exc:
        performance.set_settings(e_uci, **kwargs)
    assert exc.value.parameter == parameter
    assert performance.get_settings(e_uci)['fastpath'] is False


def test_status_when_the_tool_is_missing(mocker):
    mocker.patch.object(performance, 'FASTPATH_BIN', '/nonexistent/nexwall-fastpath')
    assert performance.fastpath_status()['reason'] == 'not-installed'


def test_ring_buffers_are_stored_and_validated(e_uci):
    performance.set_settings(e_uci, ring_buffers=True)
    assert performance.get_settings(e_uci)['ring_buffers'] is True
    performance.set_settings(e_uci, ring_buffers=False)
    assert performance.get_settings(e_uci)['ring_buffers'] is False
    with pytest.raises(ValidationError) as exc:
        performance.set_settings(e_uci, ring_buffers='yes')
    assert exc.value.parameter == 'ring_buffers'
