#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Unit tests for the live session parser (pfctl -ss -v output of FreeBSD 14).
#   python -m unittest tests/test_live.py

import ipaddress
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'security', 'layer7security', 'src', 'opnsense',
                                'scripts', 'OPNsense', 'Layer7Security'))
import live  # noqa: E402

SAMPLE = """all tcp 103.102.166.224:443 <- 10.77.0.2:36274       TIME_WAIT:TIME_WAIT
   [1367647566 + 3869246464] wscale 9  [478681889 + 4289200384] wscale 7
   age 00:00:01, expires in 00:01:29, 86:118 pkts, 5502:135189 bytes, rule 87
all tcp 192.168.1.12:56765 (10.77.0.2:36274) -> 103.102.166.224:443       TIME_WAIT:TIME_WAIT
   [478681889 + 4289200384] wscale 7  [1367647566 + 3869246464] wscale 9
   age 00:00:01, expires in 00:01:29, 86:118 pkts, 5502:135189 bytes, rule 85, allow-opts
all udp 10.77.0.1:53 <- 10.77.0.2:50953       SINGLE:MULTIPLE
   age 00:00:01, expires in 00:00:29, 1:1 pkts, 74:119 bytes, rule 87
all udp 2401:4900:8900:9fd2:be24:11ff:fe91:101[39931] -> 2001:500:c::1[53]       MULTIPLE:SINGLE
   age 00:00:01, expires in 00:00:29, 1:1 pkts, 90:777 bytes, rule 86, allow-opts
all ipv6-icmp ff02::1[134] <- fe80::6e4f:89ff:fe09:6973       NO_TRAFFIC:NO_TRAFFIC
   age 00:00:08, expires in 00:00:12, 1:0 pkts, 160:0 bytes, rule 37
all tcp 192.168.1.12:443 <- 192.168.1.3:55495       FIN_WAIT_2:FIN_WAIT_2
   [1911680690 + 512] wscale 7  [4104554745 + 65792] wscale 8
   age 01:01:44, expires in 00:00:18, 24:32 pkts, 4314:5935 bytes, rule 91
all tcp 127.0.0.1:3129 (1.1.1.1:443) <- 10.77.0.2:50000       ESTABLISHED:ESTABLISHED
   age 00:00:10, expires in 23:59:50, 5:5 pkts, 500:900 bytes, rule 9
all tcp 10.77.0.9:8080 <- 203.0.113.5:40000       ESTABLISHED:ESTABLISHED
   age 00:00:10, expires in 23:59:50, 5:5 pkts, 500:900 bytes, rule 9
"""


class ParseTest(unittest.TestCase):
    def sessions(self):
        out = []
        for st in live.parse_states(SAMPLE):
            s = live.to_session(st)
            if s:
                out.append(s)
        return out

    def test_counts_and_nat_pair(self):
        # 8 states, the outbound half of the NAT pair is dropped
        self.assertEqual(len(live.parse_states(SAMPLE)), 8)
        self.assertEqual(len(self.sessions()), 7)

    def test_client_and_server_of_an_outgoing_connection(self):
        s = self.sessions()[0]
        self.assertEqual((s['client'], s['cport'], s['server'], s['sport']), ('10.77.0.2', 36274, '103.102.166.224', 443))
        self.assertEqual((s['up'], s['down'], s['pup'], s['pdown']), (5502, 135189, 86, 118))
        self.assertEqual(s['state'], 'TIME_WAIT:TIME_WAIT')

    def test_ipv6_firewall_originated(self):
        s = self.sessions()[2]
        self.assertEqual(s['client'], '2401:4900:8900:9fd2:be24:11ff:fe91:101')
        self.assertEqual((s['cport'], s['server'], s['sport']), (39931, '2001:500:c::1', 53))

    def test_icmp_has_no_ports(self):
        s = self.sessions()[3]
        self.assertEqual(s['proto'], 'ipv6-icmp')
        self.assertEqual(s['server'], 'ff02::1')

    def test_age_with_hours(self):
        self.assertEqual(self.sessions()[4]['age'], 3600 + 60 + 44)

    def test_redirected_connection_shows_original_destination(self):
        s = self.sessions()[5]
        self.assertEqual((s['server'], s['sport']), ('1.1.1.1', 443))
        self.assertEqual(s['proxied'], '127.0.0.1:3129')

    def test_classification(self):
        nets = [ipaddress.ip_network('10.77.0.0/24')]
        fw = {'10.77.0.1', '192.168.1.12', '2401:4900:8900:9fd2:be24:11ff:fe91:101'}
        got = [live.classify(s, nets, fw) for s in self.sessions()]
        # out, dns to the firewall, firewall's own dns, icmp, gui from outside the LAN, redirected, inbound
        self.assertEqual(got[0], 'out')
        self.assertEqual(got[1], 'internal')
        self.assertEqual(got[2], 'firewall')
        self.assertEqual(got[4], 'in')
        self.assertEqual(got[5], 'out')
        self.assertEqual(got[6], 'in')

    def test_unparsable_lines_are_ignored(self):
        self.assertEqual(live.parse_states('garbage\n   age nonsense\n'), [])
        self.assertEqual(live.parse_states(''), [])

    def test_endpoint_forms(self):
        self.assertEqual(live.parse_endpoint('1.2.3.4:80'), ('1.2.3.4', 80))
        self.assertEqual(live.parse_endpoint('fe80::1[443]'), ('fe80::1', 443))
        self.assertEqual(live.parse_endpoint('10.0.0.1'), ('10.0.0.1', 0))
        self.assertEqual(live.parse_endpoint('fe80::1'), ('fe80::1', 0))


if __name__ == '__main__':
    unittest.main()
