#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Read the IPv4 address of an OpenWrt network interface section.

OpenWrt can write the address of a static interface in several forms, and the code
must accept all of them:

- ``option ipaddr '192.168.1.1'`` with ``option netmask '255.255.255.0'``
- ``option ipaddr '192.168.1.1/24'`` (CIDR, no netmask option)
- ``list ipaddr '192.168.1.1/24'`` (a list, which UCI returns as a list or tuple)
- a netmask given as a prefix length (``option netmask '24'``)
"""

import ipaddress


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [v for v in value if v not in (None, '')]
    return [value] if value != '' else []


def _first_ipv4(value):
    for item in _as_list(value):
        text = str(item).strip()
        try:
            if ipaddress.ip_interface(text).version == 4:
                return text
        except ValueError:
            continue
    return None


def get_ipv4(section):
    """
    Return ``(address, netmask)`` as strings, or ``None`` when the section has no usable IPv4
    address. ``section`` is the dict of the options of an interface.
    """
    addr = _first_ipv4(section.get('ipaddr'))
    if addr is None:
        return None
    if '/' in addr:
        iface = ipaddress.ip_interface(addr)
        return str(iface.ip), str(iface.netmask)
    masks = _as_list(section.get('netmask'))
    if not masks:
        return None
    try:
        network = ipaddress.ip_network(f'{addr}/{str(masks[0]).strip()}', strict=False)
    except ValueError:
        return None
    return addr, str(network.netmask)
