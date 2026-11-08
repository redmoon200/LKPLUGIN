#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Unit tests for the monitoring agent of the plugin (agent.py): reading the firewall log, local
# outage tracking, engine event counters, what a report contains (and what it must not), and the
# send / confirm cycle with a fake cloud server.
#   python -m unittest tests/test_agent.py

import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
SCRIPTS = os.path.join(ROOT, 'security', 'layer7security', 'src', 'opnsense', 'scripts', 'OPNsense', 'Layer7Security')
sys.path.insert(0, SCRIPTS)

import agent  # noqa: E402

LINE = ('<134>1 2026-11-08T04:38:31+00:00 OPNsense.internal filterlog 35327 - [meta sequenceId="1"] '
        '10,,,02f4bab031b57d1e30553ce08e0ec131,%s,match,%s,%s,4,0x0,,%d,4117,0,DF,%s,%s,52,%s,%s%s')


def fl(src, dport, action='block', direction='in', iface='vtnet1', proto='tcp', ttl=64):
    proto_num = {'tcp': 6, 'udp': 17, 'igmp': 2}[proto]
    tail = ',%d,%s,0,S,1,2,3' % (40000, dport) if proto in ('tcp', 'udp') else ',datalength=8'
    return LINE % (iface, action, direction, ttl, proto_num, proto, src, '104.16.0.1', tail) + '\n'


class FilterLogTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.log = os.path.join(self.td, 'filter.log')
        agent.FILTER_LOG = self.log

    def write(self, text, mode='a'):
        with open(self.log, mode) as f:
            f.write(text)

    def test_first_run_starts_at_the_end(self):
        self.write(fl('45.33.32.5', 22) * 50)
        st = {}
        out = agent.read_filter_log(st)
        self.assertEqual(out['in_blocks'], 0)
        self.write(fl('45.33.32.5', 22) * 3)
        self.assertEqual(agent.read_filter_log(st)['in_blocks'], 3)
        self.assertEqual(agent.read_filter_log(st)['in_blocks'], 0)          # nothing new: nothing counted twice

    def test_counts_only_inbound_blocks_and_ranks_public_sources(self):
        self.write('')
        st = {}
        agent.read_filter_log(st)
        text = (fl('45.33.32.9', 22) * 5 + fl('45.33.32.9', 23) * 2 + fl('104.16.0.20', 80) +
                fl('45.33.32.9', 22, action='pass') + fl('45.33.32.9', 22, direction='out') +
                fl('192.168.1.1', 0, proto='igmp') + fl('10.0.0.8', 445) * 4 + fl('45.33.32.77', 53, proto='udp') * 2)
        self.write(text)
        out = agent.read_filter_log(st)
        self.assertEqual(out['in_blocks'], 5 + 2 + 1 + 1 + 4 + 2)
        self.assertEqual(out['public_blocks'], 5 + 2 + 1 + 2)              # private sources are not "attackers"
        self.assertEqual(out['top'][0], {'ip': '45.33.32.9', 'hits': 7, 'ports': 2, 'iface': 'vtnet1', 'proto': 'tcp'})
        self.assertEqual([t['ip'] for t in out['top']], ['45.33.32.9', '45.33.32.77', '104.16.0.20'])

    def test_port_scanner_is_counted(self):
        self.write('')
        st = {}
        agent.read_filter_log(st)
        self.write(''.join(fl('45.33.32.50', p) for p in range(1000, 1030)))
        out = agent.read_filter_log(st)
        self.assertEqual(out['top'][0]['ports'], 30)
        self.assertEqual(out['scanners'], 1)

    def test_a_half_written_line_is_left_for_the_next_run(self):
        self.write('')
        st = {}
        agent.read_filter_log(st)
        line = fl('45.33.32.5', 22)
        self.write(line + line[:60])
        self.assertEqual(agent.read_filter_log(st)['in_blocks'], 1)
        self.write(line[60:])
        self.assertEqual(agent.read_filter_log(st)['in_blocks'], 1)

    def test_a_new_log_file_is_read_from_its_start(self):
        self.write('')
        st = {}
        agent.read_filter_log(st)
        self.write(fl('45.33.32.5', 22) * 4)
        agent.read_filter_log(st)
        os.unlink(self.log)                                                  # daily rotation: a new file under the same name
        self.write(fl('45.33.32.6', 22) * 2)
        self.assertEqual(agent.read_filter_log(st)['in_blocks'], 2)

    def test_missing_log_and_junk_lines_do_not_crash(self):
        agent.FILTER_LOG = os.path.join(self.td, 'nope.log')
        self.assertEqual(agent.read_filter_log({})['in_blocks'], 0)
        agent.FILTER_LOG = self.log
        self.write('')
        st = {}
        agent.read_filter_log(st)
        self.write('garbage\nfilterlog but not csv\n<134>1 x filterlog 1 - [m] 1,2,3\n' + fl('45.33.32.5', 22))
        self.assertEqual(agent.read_filter_log(st)['in_blocks'], 1)


class OutageTrackingTest(unittest.TestCase):
    def gw(self, status):
        return [{'name': 'WAN_DHCP', 'status': status}]

    def test_internet_outage_opens_after_two_failed_probes_and_closes(self):
        st = {}
        agent.track_outages(st, self.gw('none'), 0, 1000)
        self.assertEqual(st['outages'], [])
        agent.track_outages(st, self.gw('none'), 0, 1060)
        self.assertEqual(st['outages'], [{'kind': 'internet', 'start': 1000, 'end': 0}])      # started at the first failed probe
        agent.track_outages(st, self.gw('none'), 0, 1120)
        self.assertEqual(len(st['outages']), 1)
        agent.track_outages(st, self.gw('none'), 3, 1180)
        self.assertEqual(st['outages'], [{'kind': 'internet', 'start': 1000, 'end': 1180}])

    def test_a_single_failed_probe_is_not_an_outage(self):
        st = {}
        agent.track_outages(st, self.gw('none'), 0, 1000)
        agent.track_outages(st, self.gw('none'), 2, 1060)
        agent.track_outages(st, self.gw('none'), 0, 1120)
        self.assertEqual(st['outages'], [])

    def test_gateway_down_is_its_own_record(self):
        st = {}
        agent.track_outages(st, self.gw('down'), 3, 2000)
        agent.track_outages(st, self.gw('force_down'), 3, 2060)
        self.assertEqual(st['outages'], [{'kind': 'gw:WAN_DHCP', 'start': 2000, 'end': 0}])
        agent.track_outages(st, self.gw('none'), 3, 2120)
        self.assertEqual(st['outages'][0]['end'], 2120)

    def test_the_list_is_capped(self):
        st = {'outages': [{'kind': 'internet', 'start': i, 'end': i + 1} for i in range(80)]}
        agent.track_outages(st, self.gw('none'), 3, 5000)
        self.assertEqual(len(st['outages']), agent.MAX_OUTAGES)
        self.assertEqual(st['outages'][-1]['start'], 79)


class CountersTest(unittest.TestCase):
    def test_cpu_percent_from_two_samples(self):
        st = {}
        with mock.patch.object(agent, 'sysctl', return_value='100 0 50 10 840'):
            self.assertIsNone(agent.cpu_percent(st))
        with mock.patch.object(agent, 'sysctl', return_value='160 0 90 20 930'):       # busy 100, idle 90
            self.assertEqual(agent.cpu_percent(st), 55.0)
        with mock.patch.object(agent, 'sysctl', return_value='junk'):
            self.assertIsNone(agent.cpu_percent(st))

    def test_public_address_check(self):
        for ip in ('8.8.8.8', '45.33.32.156'):
            self.assertTrue(agent.public_v4(ip), ip)
        for ip in ('10.1.1.1', '192.168.0.4', '172.20.1.1', '127.0.0.1', '169.254.1.1', '224.0.0.1', 'x', '2001:db8::1', '100.64.0.1'):
            self.assertFalse(agent.public_v4(ip), ip)

    def test_engine_events_count_threats_without_naming_clients(self):
        td = tempfile.mkdtemp()
        agent.ENGINE_DB = os.path.join(td, 'l7.db')
        con = sqlite3.connect(agent.ENGINE_DB)
        con.execute('CREATE TABLE events(id INTEGER PRIMARY KEY, ts INTEGER, type TEXT, client TEXT, server TEXT, app TEXT, category TEXT, host TEXT, policy TEXT, detail TEXT)')
        now = int(time.time())
        rows = [(now, 'block', '10.0.0.5', '1.2.3.4', '', 'Botnet and command-and-control', 'c2.example.net', 'p', ''),
                (now, 'block', '10.0.0.5', '1.2.3.4', '', 'Botnet and command-and-control', 'c2.example.net', 'p', ''),
                (now, 'block', '10.0.0.6', '5.6.7.8', '', 'Phishing', 'login.fake.example', 'p', ''),
                (now, 'block', '10.0.0.7', '9.9.9.9', '', 'Social networks', 'social.example', 'p', ''),
                (now, 'mac-spoof', '10.0.0.8', '', '', '', '', '', ''), (now, 'device-new', '10.0.0.9', '', '', '', '', '', ''),
                (now - 500, 'block', '10.0.0.5', '1.2.3.4', '', 'Malware', 'old.example', 'p', '')]
        con.executemany('INSERT INTO events(ts,type,client,server,app,category,host,policy,detail) VALUES(?,?,?,?,?,?,?,?,?)', rows)
        con.commit()
        con.close()
        out = agent.engine_events(now - 60)
        self.assertEqual((out['blocks'], out['threat_hits'], out['threat_clients'], out['mac_spoofs'], out['new_devices']), (4, 3, 2, 1, 1))
        self.assertEqual(out['threat_top'][0], {'target': 'c2.example.net', 'category': 'Botnet and command-and-control', 'hits': 2})
        self.assertNotIn('10.0.0.5', json.dumps(out))
        agent.ENGINE_DB = os.path.join(td, 'missing.db')
        self.assertEqual(agent.engine_events(0)['blocks'], 0)

    def test_av_detections(self):
        td = tempfile.mkdtemp()
        agent.AV_DB = os.path.join(td, 'av.db')
        con = sqlite3.connect(agent.AV_DB)
        con.execute('CREATE TABLE av_events(id INTEGER PRIMARY KEY, ts INTEGER)')
        con.executemany('INSERT INTO av_events(ts) VALUES(?)', [(int(time.time()),), (int(time.time()) - 9000,)])
        con.commit()
        con.close()
        self.assertEqual(agent.av_detections(int(time.time()) - 60), 1)

    def test_gateways_are_slimmed_and_garbage_is_ignored(self):
        data = json.dumps([{'name': 'WAN', 'address': '1.2.3.4', 'status': 'none', 'loss': '0.0', 'delay': '4.1', 'stddev': '~', 'secret': 'x'}, 'junk'])
        with mock.patch.object(agent, 'run', return_value=data):
            g = agent.gateways()
        self.assertEqual(g, [{'name': 'WAN', 'address': '1.2.3.4', 'status': 'none', 'loss': 0.0, 'delay': 4.1, 'stddev': None}])
        with mock.patch.object(agent, 'run', return_value='not json'):
            self.assertEqual(agent.gateways(), [])


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        agent.STATE = os.path.join(self.td, 'agent.json')
        agent.FILTER_LOG = os.path.join(self.td, 'none.log')
        agent.ENGINE_DB = os.path.join(self.td, 'none.db')
        agent.AV_DB = os.path.join(self.td, 'none.av')
        agent.ENGINE_STATUS = os.path.join(self.td, 'status.json')
        self.cfg = {'general': {'enabled': '1', 'feedUrl': 'http://cloud.example:8080/feeds'}}
        self.patches = [mock.patch.object(agent.cloudlib, 'settings', return_value=self.cfg),
                        mock.patch.object(agent, 'run', return_value=''), mock.patch.object(agent, 'probe_internet', return_value=3),
                        mock.patch.object(agent, 'disk_percent', return_value=12.0),
                        mock.patch.object(agent.lc, 'install_id', return_value='1234-ABCD-5678-EF01'),
                        mock.patch.object(agent.lc, 'current_key', return_value='KEY'), mock.patch.object(agent.lc, 'plugin_version', return_value='0.6.0'),
                        mock.patch.object(agent.lc, 'last_feed_update', return_value=5), mock.patch.object(agent.lc, 'read_state', return_value={'server_state': 'active'}),
                        mock.patch.object(agent.time, 'sleep'), mock.patch.object(agent.update, 'summary', return_value={'plugin': {}, 'firmware': {}}), mock.patch.object(agent.os, 'uname', create=True, return_value=mock.Mock(nodename='fw-test')), mock.patch.object(agent.os, 'getloadavg', create=True, return_value=(0.5, 0.4, 0.3))]
        for p in self.patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self.patches])

    def test_report_has_only_expected_parts_and_no_client_data(self):
        st = {}
        rep = agent.gather(st, self.cfg, int(time.time()))
        self.assertEqual(sorted(rep), ['feedsUpdated', 'gateways', 'health', 'hostname', 'install_id', 'internet', 'key', 'license', 'opnsense', 'outages',
                                       'security', 'seq', 'support', 'ts', 'updates', 'version'])
        self.assertEqual(rep['support'], {'level': 'off'})                  # only the consent level, nothing else
        self.assertEqual(sorted(rep['security']), ['av_detections', 'blocks', 'in_blocks', 'mac_spoofs', 'new_devices', 'public_blocks', 'scanners',
                                                   'threat_clients', 'threat_hits', 'threat_top', 'top', 'window'])
        self.assertEqual(rep['internet'], {'ok': 3, 'of': 3})

    def test_off_switch_sends_nothing(self):
        self.cfg['general']['monitoring'] = '0'
        with mock.patch.object(agent, 'post') as post:
            res = agent.beat(True)
        post.assert_not_called()
        self.assertFalse(res['ok'])
        self.assertIn('switched off', res['skipped'])

    def test_no_server_address_sends_nothing(self):
        self.cfg['general']['feedUrl'] = ''
        with mock.patch.object(agent, 'post') as post:
            res = agent.beat(True)
        post.assert_not_called()
        self.assertIn('address', res['error'])

    def test_token_and_confirmed_outages_are_kept_correctly(self):
        sent = []

        def fake(url, payload, token, timeout=20):
            sent.append((url, token, payload))
            return {'ok': True, 'token': 'T' * 48, 'got_outages': [100], 'server_time': 1, 'open_alerts': 2}
        agent.save_state({'outages': [{'kind': 'internet', 'start': 100, 'end': 160}, {'kind': 'gw:WAN', 'start': 200, 'end': 0},
                                      {'kind': 'internet', 'start': 300, 'end': 360}]})
        with mock.patch.object(agent, 'post', side_effect=fake):
            res = agent.beat(True)
        self.assertTrue(res['ok'])
        self.assertEqual(sent[0][0], 'http://cloud.example:8080/api/v1/beat')
        self.assertEqual(sent[0][1], '')                                    # first report: no token yet
        st = agent.load_state()
        self.assertEqual(st['token'], 'T' * 48)
        self.assertEqual([o['start'] for o in st['outages']], [200, 300])   # only the confirmed one was dropped; the open one stays
        self.assertEqual(st['alerts_open'], 2)
        with mock.patch.object(agent, 'post', side_effect=fake):
            agent.beat(True)
        self.assertEqual(sent[1][1], 'T' * 48)                              # later reports carry the token
        self.assertEqual(oct(os.stat(agent.STATE).st_mode & 0o777), oct(0o600) if os.name != 'nt' else oct(os.stat(agent.STATE).st_mode & 0o777))

    def test_a_failed_send_keeps_the_data_for_next_time(self):
        agent.save_state({'last_ok': 111, 'outages': [{'kind': 'internet', 'start': 100, 'end': 160}]})
        with mock.patch.object(agent, 'post', return_value={'ok': False, 'error': 'cannot reach the server (timed out)'}):
            res = agent.beat(True)
        self.assertFalse(res['ok'])
        st = agent.load_state()
        self.assertEqual(st['last_ok'], 111)                                # the next report still covers the gap
        self.assertEqual(len(st['outages']), 1)
        self.assertIn('cannot reach', st['error'])


if __name__ == '__main__':
    unittest.main()
