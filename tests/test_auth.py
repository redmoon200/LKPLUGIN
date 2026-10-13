#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Unit tests for the sign-in sessions (auth.py) and the portal helpers
# (portal.py): session lifetime, idle timeout, files for the engine and pf, the
# login throttle and the redirect target checks. pf is never touched.
#   python -m unittest tests/test_auth.py

import json
import os
import sys
import tempfile
import time
import unittest

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'security', 'layer7security', 'src',
                       'opnsense', 'scripts', 'OPNsense', 'Layer7Security')
sys.path.insert(0, SCRIPTS)

TMP = tempfile.mkdtemp(prefix='l7auth-')
os.environ['L7_BASE'] = TMP
os.environ['L7_CONF_DIR'] = TMP

import auth  # noqa: E402
import portal  # noqa: E402


def configure(**kw):
    cfg = {'sessionHours': 8, 'idleMinutes': 0, 'bypass': [], 'networks': [{'net': '10.77.0.0/24', 'ip': '10.77.0.1'}],
           'port': 8444, 'title': 'T', 'message': 'M', 'server': 'Local Database', 'groups': []}
    cfg.update(kw)
    with open(auth.PORTAL_JSON, 'w') as f:
        json.dump(cfg, f)
    with open(auth.USER_TABLES, 'w') as f:
        json.dump({'3': ['Alice']}, f)


class SessionTest(unittest.TestCase):
    def setUp(self):
        auth.pf_replace = lambda table, path: self.pf.append((table, open(path).read()))
        self.killed = []
        auth.kill_states = lambda ip: self.killed.append(ip)
        self.pf = []
        if os.path.exists(auth.DB):
            os.unlink(auth.DB)
        configure()

    def test_login_writes_the_files_for_engine_and_pf(self):
        auth.login('10.77.0.2', 'alice', 'aa:bb:cc:dd:ee:ff')
        self.assertEqual(open(auth.SESSIONS_TSV).read(), '10.77.0.2\talice\n')
        self.assertEqual(open(auth.OK_FILE).read(), '10.77.0.2\n')
        tables = dict(self.pf)
        self.assertIn('l7_auth_ok', tables)
        self.assertEqual(tables['l7_usr_3'], '10.77.0.2\n')          # the policy that names Alice (case-insensitive)

    def test_bypass_networks_stay_in_the_table(self):
        configure(bypass=['10.77.0.50', '10.77.1.0/24'])
        auth.login('10.77.0.2', 'bob')
        lines = open(auth.OK_FILE).read().split()
        self.assertEqual(sorted(lines), ['10.77.0.2', '10.77.0.50/32', '10.77.1.0/24'])
        self.assertEqual(open(auth.SESSIONS_TSV).read(), '10.77.0.2\tbob\n')

    def test_logout_and_log(self):
        auth.login('10.77.0.2', 'alice')
        self.assertTrue(auth.logout('10.77.0.2', 'admin-logout', 'by admin'))
        self.assertFalse(auth.logout('10.77.0.2'))
        self.assertEqual(open(auth.SESSIONS_TSV).read(), '')
        self.assertEqual(self.killed, ['10.77.0.2'])
        kinds = [r['type'] for r in auth.recent_log(10)]
        self.assertEqual(kinds[:2], ['admin-logout', 'login'])
        self.assertEqual(auth.status()['active'], 0)

    def test_session_time_runs_out(self):
        auth.login('10.77.0.2', 'alice', hours=1)
        con = auth.connect()
        with con:
            con.execute('UPDATE sessions SET expires=?', (int(time.time()) - 5,))
        con.close()
        self.assertEqual(auth.expire(), 1)
        self.assertEqual(auth.sessions(), [])
        self.assertEqual(self.killed, ['10.77.0.2'])

    def test_idle_sessions_end(self):
        configure(idleMinutes=10)
        auth.login('10.77.0.2', 'alice')
        con = auth.connect()
        with con:
            con.execute('UPDATE sessions SET last_active=?', (int(time.time()) - 3600,))
        con.close()
        auth.last_activity = lambda ips: {}
        self.assertEqual(auth.expire(), 1)

    def test_bad_addresses_are_refused(self):
        with self.assertRaises(ValueError):
            auth.login('not-an-ip; rm -rf /', 'x')
        self.assertFalse(auth.logout('bogus'))

    def test_second_login_from_the_same_address_replaces_the_first(self):
        auth.login('10.77.0.2', 'alice')
        auth.login('10.77.0.2', 'bob')
        self.assertEqual([r['user'] for r in auth.sessions()], ['bob'])


class PortalTest(unittest.TestCase):
    def setUp(self):
        configure()
        portal.fails.clear()
        portal.locked.clear()

    def test_redirect_targets_are_checked(self):
        self.assertEqual(portal.safe_next('http://example.com/a?b=1'), 'http://example.com/a?b=1')
        self.assertEqual(portal.safe_next('https://sub.example.com/'), 'https://sub.example.com/')
        for bad in ('javascript:alert(1)', 'file:///etc/passwd', '//evil.example', 'http://exa mple.com/', 'http://%00.example/', ''):
            self.assertEqual(portal.safe_next(bad), '', bad)
        self.assertEqual(portal.safe_next('http://example.com/' + 'a' * 900), '')

    def test_form_token_is_bound_to_the_address(self):
        tok = portal.token_for('10.77.0.2')
        self.assertTrue(portal.token_ok('10.77.0.2', tok))
        self.assertFalse(portal.token_ok('10.77.0.3', tok))
        self.assertFalse(portal.token_ok('10.77.0.2', 'x' * 32))
        self.assertFalse(portal.token_ok('10.77.0.2', ''))

    def test_lockout_after_repeated_failures(self):
        for _ in range(portal.THROTTLE_FAILS - 1):
            self.assertFalse(portal.record_fail('10.77.0.2'))
        self.assertTrue(portal.record_fail('10.77.0.2'))
        self.assertGreater(portal.throttled('10.77.0.2'), 0)
        self.assertEqual(portal.throttled('10.77.0.9'), 0)

    def test_firewall_address_follows_the_clients_network(self):
        configure(networks=[{'net': '10.77.0.0/24', 'ip': '10.77.0.1'}, {'net': '10.88.0.0/24', 'ip': '10.88.0.1'}])
        self.assertEqual(portal.firewall_address_for('10.88.0.20'), '10.88.0.1')
        self.assertEqual(portal.firewall_address_for('10.77.0.20'), '10.77.0.1')
        self.assertEqual(portal.firewall_address_for('192.0.2.5'), '10.77.0.1')       # falls back to the first network

    def test_text_is_escaped_on_the_pages(self):
        configure(title='<script>x</script>', message='"quoted" & <b>')
        class Fake:
            client = lambda self: '10.77.0.2'
        page = portal.Handler.login_form(Fake(), '', '<img src=x>', '').decode()
        self.assertNotIn('<script>x', page)
        self.assertNotIn('<img src=x>', page)
        self.assertIn('&lt;img src=x&gt;', page)


if __name__ == '__main__':
    unittest.main()
