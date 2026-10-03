#!/usr/bin/python3

#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Performance settings shared by the DPI and the IPS pages: how many threads the traffic engine uses, the fast path for
connections both engines are finished with (see nexwall-fastpath) and the spreading of the network load across the CPU
cores. The fast path and the steering act on all traffic, so both pages show the same switches.
"""

import json
import os
import subprocess

from euci import EUci

from nethsec import utils
from nethsec.utils import ValidationError

FASTPATH_BIN = '/usr/sbin/nexwall-fastpath'
DPI_THREAD_CHOICES = ('auto', '1', '2', '3', '4')
MAX_FORWARD_INSTANCES = 4


def cpu_count() -> int:
    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return os.cpu_count() or 1


def auto_dpi_threads(cores: int) -> int:
    """Same rule as ns-netifyd-configure: half of the cores for the traffic engine, 1 to 4."""
    return max(1, min(MAX_FORWARD_INSTANCES, cores // 2))


def _globals_section(e_uci: EUci):
    sections = utils.get_all_by_type(e_uci, 'network', 'globals')
    return next(iter(sections), None)


def get_settings(e_uci: EUci) -> dict:
    """
    Returns:
        dict with "dpi_threads" ("auto" or "1" to "4"), "dpi_threads_auto" (what "auto" means on this hardware),
        "fastpath", "packet_steering" and "ring_buffers" (bool) and "cpu_count"
    """
    threads = str(e_uci.get('dpi', 'engine', 'threads', default='auto')).strip().lower()
    cores = cpu_count()
    section = _globals_section(e_uci)
    steering = str(e_uci.get('network', section, 'packet_steering', default='0')) if section else '0'
    return {
        'dpi_threads': threads if threads in DPI_THREAD_CHOICES else 'auto',
        'dpi_threads_auto': auto_dpi_threads(cores),
        'fastpath': str(e_uci.get('nexwall_perf', 'main', 'fastpath', default='0')) == '1',
        'packet_steering': steering in ('1', '2'),
        'ring_buffers': str(e_uci.get('nexwall_perf', 'main', 'ring_buffers', default='0')) == '1',
        'cpu_count': cores,
    }


def set_settings(e_uci: EUci, dpi_threads=None, fastpath=None, packet_steering=None, ring_buffers=None):
    """
    Store the given settings (None leaves one as it is). Applied when the changes are committed: the DPI service,
    the fast path and the packet steering all reload on their configuration.

    Raises:
        - ValidationError: if a value is not one of the allowed ones
    """
    if dpi_threads is not None and str(dpi_threads) not in DPI_THREAD_CHOICES:
        raise ValidationError('dpi_threads', 'invalid', str(dpi_threads))
    for name, value in (('fastpath', fastpath), ('packet_steering', packet_steering), ('ring_buffers', ring_buffers)):
        if value is not None and not isinstance(value, bool):
            raise ValidationError(name, 'invalid', str(value))

    if dpi_threads is not None:
        if e_uci.get('dpi', 'engine', default=None) is None:
            e_uci.set('dpi', 'engine', 'engine')
        e_uci.set('dpi', 'engine', 'threads', str(dpi_threads))
        e_uci.save('dpi')
    if fastpath is not None or ring_buffers is not None:
        if e_uci.get('nexwall_perf', 'main', default=None) is None:
            e_uci.set('nexwall_perf', 'main', 'main')
        if fastpath is not None:
            e_uci.set('nexwall_perf', 'main', 'fastpath', '1' if fastpath else '0')
        if ring_buffers is not None:
            e_uci.set('nexwall_perf', 'main', 'ring_buffers', '1' if ring_buffers else '0')
        e_uci.save('nexwall_perf')
    if packet_steering is not None:
        section = _globals_section(e_uci)
        if section is None:
            section = 'globals'
            e_uci.set('network', section, 'globals')
        e_uci.set('network', section, 'packet_steering', '1' if packet_steering else '0')
        e_uci.save('network')


def fastpath_status() -> dict:
    """What the fast path is doing right now: enabled, active, devices, min_bytes, offloaded_flows, reason."""
    try:
        out = subprocess.run([FASTPATH_BIN, 'status'], capture_output=True, text=True, timeout=10, check=False)
        return json.loads(out.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return {'enabled': False, 'active': False, 'reason': 'not-installed'}
