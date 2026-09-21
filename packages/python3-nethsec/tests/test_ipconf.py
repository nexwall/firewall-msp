#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

import unittest

from nethsec import ipconf


class GetIpv4Test(unittest.TestCase):
    def test_separate_netmask(self):
        self.assertEqual(ipconf.get_ipv4({'ipaddr': '192.168.1.1', 'netmask': '255.255.255.0'}),
                         ('192.168.1.1', '255.255.255.0'))

    def test_cidr_without_netmask(self):
        # what OpenWrt 25.12 writes for the default interface: this crashed the DNS and DHCP page
        self.assertEqual(ipconf.get_ipv4({'ipaddr': '192.168.1.1/24'}), ('192.168.1.1', '255.255.255.0'))

    def test_list_and_tuple(self):
        self.assertEqual(ipconf.get_ipv4({'ipaddr': ['10.0.0.1/8']}), ('10.0.0.1', '255.0.0.0'))
        self.assertEqual(ipconf.get_ipv4({'ipaddr': ('172.16.5.1/20', '10.9.9.9/24')}),
                         ('172.16.5.1', '255.255.240.0'))

    def test_netmask_as_prefix(self):
        self.assertEqual(ipconf.get_ipv4({'ipaddr': '10.1.2.3', 'netmask': '16'}), ('10.1.2.3', '255.255.0.0'))

    def test_cidr_wins_over_netmask(self):
        self.assertEqual(ipconf.get_ipv4({'ipaddr': '10.1.2.3/24', 'netmask': '255.255.0.0'}),
                         ('10.1.2.3', '255.255.255.0'))

    def test_unusable_sections(self):
        for section in ({}, {'ipaddr': ''}, {'ipaddr': []}, {'ipaddr': '192.168.1.1'},
                        {'ipaddr': '192.168.1.1', 'netmask': 'bad'}, {'ipaddr': 'not-an-ip'},
                        {'ipaddr': ['2001:db8::1/64']}, {'proto': 'dhcp'}):
            self.assertIsNone(ipconf.get_ipv4(section), msg=str(section))

    def test_skips_invalid_entries_in_a_list(self):
        self.assertEqual(ipconf.get_ipv4({'ipaddr': ['2001:db8::1/64', 'junk', '192.168.7.1/24']}),
                         ('192.168.7.1', '255.255.255.0'))


class GetCidrTest(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(ipconf.get_cidr({'ipaddr': '192.168.1.1', 'netmask': '255.255.255.0'}), '192.168.1.1/24')
        self.assertEqual(ipconf.get_cidr({'ipaddr': '192.168.1.1/24'}), '192.168.1.1/24')
        self.assertEqual(ipconf.get_cidr({'ipaddr': ['192.168.1.1/24']}), '192.168.1.1/24')

    def test_several_addresses_are_left_alone(self):
        self.assertIsNone(ipconf.get_cidr({'ipaddr': ['192.168.1.1/24', '10.0.0.1/8']}))

    def test_none(self):
        self.assertIsNone(ipconf.get_cidr({}))


if __name__ == '__main__':
    unittest.main()
