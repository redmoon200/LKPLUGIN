#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Unit tests for the firewall side of remote support (support.py): every reason a signed command must be refused, what the read actions
# return, the audit log and polling. Commands are signed with a throw-away key (tests/vendor_sign.py).
#   python -m unittest tests/test_support.py

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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_TMP = tempfile.mkdtemp(prefix='l7sup-')
os.environ['L7_BASE'] = os.path.join(_TMP, 'fwbase')
_KEYDIR = tempfile.mkdtemp(prefix='l7supkey-')
PRIV = os.path.join(_KEYDIR, 'vendor.pem')
OTHER = os.path.join(_KEYDIR, 'other.pem')

import vendor_sign  # noqa: E402

PUB_PEM = vendor_sign.generate_keypair(PRIV)
OTHER_PUB = vendor_sign.generate_keypair(OTHER)

import support  # noqa: E402

FW = '1234-ABCD-5678-EF01'
UUID1 = '0a1b2c3d-1111-2222-3333-444455556666'


def need_level(action):
    return 'view' if action in support.READ else 'manage'


def signed(action='overview', params=None, fw=FW, level=None, iat=None, exp=None, cmd_id=None, key=None):
    iat = int(time.time()) if iat is None else iat
    return vendor_sign.command_envelope(cmd_id or os.urandom(12).hex(), fw, action, params or {}, level or need_level(action), iat,
                                        iat + 600 if exp is None else exp, key or PRIV)


def use_test_key(case):
    """trust the test key for the length of one test"""
    for p in (mock.patch.object(support, 'public_pem', return_value=PUB_PEM), mock.patch.object(support, 'OPENSSL', vendor_sign.OPENSSL)):
        p.start()
        case.addCleanup(p.stop)


class FirewallBase(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp(prefix='l7fw-')
        for name, fn in (('AUDIT', 'audit.jsonl'), ('SEEN', 'seen.json'), ('PENDING', 'pending.json')):
            setattr(support, name, os.path.join(self.td, fn))
        use_test_key(self)
        self.cfg = {'general': {'remoteSupport': 'manage'}}
        p = mock.patch.object(support.cloudlib, 'settings', side_effect=lambda: self.cfg)
        p.start()
        self.addCleanup(p.stop)

    def level(self, lvl):
        self.cfg['general']['remoteSupport'] = lvl


class VerifyTest(FirewallBase):
    def test_a_good_command_is_accepted(self):
        self.assertEqual(support.verify(signed('overview'), FW), (True, ''))

    def test_every_tampering_is_refused(self):
        env = signed('web_rule', {'op': 'add', 'kind': 'domain', 'value': 'a.example.com', 'rule_action': 'block', 'minutes': 0, 'note': ''})
        for field, value in (('action', 'apply'), ('fw', '0000-0000-0000-0000'), ('exp', env['exp'] + 100), ('iat', env['iat'] - 5), ('id', 'a' * 24), ('level', 'view'),
                             ('params', {'op': 'add', 'kind': 'domain', 'value': 'evil.example.com', 'rule_action': 'allow'}), ('v', 2)):
            bad = dict(env)
            bad[field] = value
            ok, why = support.verify(bad, FW)
            self.assertFalse(ok, field)
        bad = dict(env)
        bad['sig'] = env['sig'][:-4] + 'AAAA'
        self.assertFalse(support.verify(bad, FW)[0])

    def test_signature_of_another_key_is_refused(self):
        ok, why = support.verify(signed('overview', key=OTHER), FW)
        self.assertFalse(ok)
        self.assertIn('signature', why)

    def test_a_license_style_signature_is_not_a_command(self):
        env = signed('overview')
        body = {k: env[k] for k in ('v', 'id', 'fw', 'action', 'params', 'level', 'iat', 'exp')}
        import base64
        with tempfile.TemporaryDirectory() as td:
            m, s = os.path.join(td, 'm'), os.path.join(td, 's')
            with open(m, 'wb') as f:
                f.write(b'L7LIC1\0' + vendor_sign.canonical(body).encode())            # the license prefix instead of the command prefix
            vendor_sign._run(['pkeyutl', '-sign', '-inkey', PRIV, '-rawin', '-in', m, '-out', s])
            with open(s, 'rb') as f:
                env['sig'] = base64.b64encode(f.read()).decode()
        self.assertFalse(support.verify(env, FW)[0])

    def test_time_rules(self):
        now = int(time.time())
        self.assertIn('expired', support.verify(signed('overview', iat=now - 700, exp=now - 100), FW)[1])
        self.assertIn('future', support.verify(signed('overview', iat=now + 500, exp=now + 900), FW)[1])
        self.assertIn('too long', support.verify(signed('overview', iat=now, exp=now + 5000), FW)[1])

    def test_shape_errors(self):
        for junk in (None, 'x', [], {}, {'v': 1}, {'sig': 'x'}):
            self.assertFalse(support.verify(junk, FW)[0])
        env = signed('overview')
        env['sig'] = '!!!notbase64'
        self.assertFalse(support.verify(env, FW)[0])

    def test_unknown_action_and_wrong_level_are_refused_even_when_signed(self):
        self.assertIn('unknown action', support.verify(signed('shell', {}, level='manage'), FW)[1])
        self.assertIn('level', support.verify(signed('apply', level='view'), FW)[1])


class ExecuteTest(FirewallBase):
    def run_cmd(self, **kw):
        return support.execute(signed(**kw), FW)

    def test_view_runs_reads_and_is_audited(self):
        self.level('view')
        res = self.run_cmd(action='config')
        self.assertTrue(res['ok'])
        self.assertIn('data', res)
        row = support.audit_tail()[0]
        self.assertEqual((row['action'], row['ok']), ('config', True))

    def test_off_refuses_everything(self):
        self.level('off')
        res = self.run_cmd(action='overview')
        self.assertFalse(res['ok'])
        self.assertIn('switched off', res['message'])
        self.assertIn('refused', support.audit_tail()[0]['result'])

    def test_view_refuses_changes_even_with_a_valid_signature(self):
        self.level('view')
        with mock.patch.object(support, 'php') as php:
            res = self.run_cmd(action='web_rule', params={'op': 'add', 'kind': 'domain', 'value': 'a.example.com', 'rule_action': 'block', 'minutes': 0, 'note': ''})
        php.assert_not_called()
        self.assertIn('only allows viewing', res['message'])

    def test_consent_is_checked_at_the_moment_of_running(self):
        self.level('manage')
        env = signed('apply')
        self.level('off')                                              # the owner changed their mind after the command was issued
        with mock.patch.object(support, 'configd') as cd:
            res = support.execute(env, FW)
        cd.assert_not_called()
        self.assertFalse(res['ok'])

    def test_manage_runs_changes(self):
        with mock.patch.object(support, 'php', return_value=(True, 'Block rule for a.example.com added.', {})) as php:
            res = self.run_cmd(action='web_rule', params={'op': 'add', 'kind': 'domain', 'value': 'A.Example.com', 'rule_action': 'block', 'minutes': 30, 'note': 'x'})
        self.assertTrue(res['ok'])
        php.assert_called_once()
        self.assertEqual(php.call_args[0][0], 'web_rule')
        self.assertEqual(php.call_args[0][1]['value'], 'a.example.com')
        self.assertEqual(support.audit_tail()[0]['detail'], 'add block a.example.com')

    def test_a_command_runs_only_once(self):
        env = signed('apply')
        with mock.patch.object(support, 'configd', return_value=(True, '')) as cd:
            self.assertTrue(support.execute(env, FW)['ok'])
            second = support.execute(env, FW)
        self.assertEqual(cd.call_count, 1)
        self.assertIn('replay', second['message'])

    def test_a_refused_command_cannot_be_replayed_later_either(self):
        self.level('off')
        env = signed('apply')
        support.execute(env, FW)
        self.level('manage')
        with mock.patch.object(support, 'configd', return_value=(True, '')) as cd:
            res = support.execute(env, FW)
        cd.assert_not_called()
        self.assertFalse(res['ok'])

    def test_for_another_firewall(self):
        res = support.execute(signed('overview', fw='0000-0000-0000-0000'), FW)
        self.assertIn('another firewall', res['message'])

    def test_exceptions_become_a_failed_result(self):
        with mock.patch.object(support, 'read_overview', side_effect=RuntimeError('boom')):
            res = self.run_cmd(action='overview')
        self.assertFalse(res['ok'])
        self.assertIn('boom', res['message'])

    def test_audit_log_is_capped_and_newest_first(self):
        for i in range(support.KEEP_AUDIT + 20):
            support.audit({'id': str(i), 'action': 'overview', 'ok': True, 'result': 'x', 'detail': ''})
        rows = support.audit_tail(1000)
        self.assertEqual(len(rows), support.KEEP_AUDIT)
        self.assertEqual(rows[0]['id'], str(support.KEEP_AUDIT + 19))

    def test_summaries_never_contain_option_secrets_beyond_a_short_value(self):
        self.assertLessEqual(len(support.summary('set_option', {'path': 'general.dnsBlock', 'value': 'x' * 500})), 120)



class ReadActionsTest(FirewallBase):
    def setUp(self):
        super().setUp()
        self.cfgxml = os.path.join(self.td, 'config.xml')
        with open(self.cfgxml, 'w') as f:
            f.write('<opnsense><OPNsense><layer7security><general><enabled>1</enabled><feedUrl>http://cloud:8080/feeds</feedUrl><retention>7</retention>'
                    '<remoteSupport>manage</remoteSupport></general><av><feedAuthKey>TOPSECRET</feedAuthKey><enabled>1</enabled></av>'
                    '<auth><adminPassword>HASHED</adminPassword><title>Portal</title></auth>'
                    '<webcontrol><enabled>1</enabled><rule uuid="%s"><enabled>1</enabled><kind>domain</kind><value>bad.example.com</value><action>block</action></rule></webcontrol>'
                    '<policies><policy uuid="aaaaaaaa-1111-2222-3333-444444444444"><name>Kids</name><enabled>1</enabled></policy></policies>'
                    '</layer7security></OPNsense></opnsense>' % UUID1)
        p = mock.patch.object(support.cloudlib, 'CONFIG', self.cfgxml)
        p.start()
        self.addCleanup(p.stop)
        support.ENGINE_DB = os.path.join(self.td, 'l7.db')
        con = sqlite3.connect(support.ENGINE_DB)
        con.execute('CREATE TABLE events(id INTEGER PRIMARY KEY, ts INTEGER, type TEXT, client TEXT, server TEXT, app TEXT, category TEXT, host TEXT, policy TEXT, detail TEXT)')
        con.execute('CREATE TABLE flows(id INTEGER PRIMARY KEY, ts_start INTEGER, ts_end INTEGER, client TEXT, app TEXT, category TEXT, host TEXT, bytes_up INTEGER DEFAULT 0,'
                    ' bytes_down INTEGER DEFAULT 0, action TEXT, policy TEXT)')
        now = int(time.time())
        con.executemany('INSERT INTO events(ts,type,client,server,app,category,host,policy,detail) VALUES(?,?,?,?,?,?,?,?,?)',
                        [(now, 'block', '10.0.0.5', '1.2.3.4', 'TikTok', 'Social', 'tiktok.com', 'Kids', ''), (now, 'block', '10.0.0.6', '1.2.3.4', 'TikTok', 'Social', 'tiktok.com', 'Kids', ''),
                         (now - 10 * 3600, 'block', '10.0.0.5', '5.5.5.5', 'X', 'Ads', 'old.example', 'Kids', '')])
        con.executemany('INSERT INTO flows(ts_start,ts_end,client,app,category,host,bytes_up,bytes_down,action,policy) VALUES(?,?,?,?,?,?,?,?,?,?)',
                        [(now, now, '10.0.0.5', 'YouTube', 'Streaming', 'youtube.com', 10, 90, 'allow', ''), (now, now, '10.0.0.6', 'YouTube', 'Streaming', 'youtube.com', 5, 45, None, ''),
                         (now, now, '10.0.0.5', 'TikTok', 'Social', 'tiktok.com', 1, 1, 'block', 'Kids')])
        con.commit()
        con.close()

    def test_config_is_complete_but_has_no_secrets(self):
        tree = support.config_tree()
        text = json.dumps(tree)
        self.assertNotIn('TOPSECRET', text)
        self.assertNotIn('HASHED', text)
        self.assertIn('Portal', text)
        self.assertEqual(tree['webcontrol']['rule'][0]['uuid'], UUID1)
        self.assertEqual(tree['policies']['policy'][0]['name'], 'Kids')

    def test_overview_counts_and_hides_the_server_address(self):
        o = support.read_overview()
        self.assertEqual((o['counts']['webRules'], o['counts']['policies']), (1, 1))
        self.assertNotIn('feedUrl', o['general'])

    def test_sites_blocked_and_allowed(self):
        s = support.read_sites(6, 10)
        self.assertEqual([(b['host'], b['hits']) for b in s['blocked']], [('tiktok.com', 2)])             # the 10 hour old event is outside 6 hours
        self.assertEqual([(a['host'], a['hits'], a['clients']) for a in s['allowed']], [('youtube.com', 2, 2)])
        self.assertEqual(s['rules'][0]['value'], 'bad.example.com')

    def test_events_show_clients_only_with_full_support(self):
        self.level('view')
        rows = support.execute(signed('events', {'limit': 5}), FW)['data']['rows']
        self.assertTrue(rows)
        self.assertNotIn('client', rows[0])
        self.level('manage')
        rows = support.execute(signed('events', {'limit': 5}), FW)['data']['rows']
        self.assertIn('client', rows[0])

    def test_missing_database_gives_empty_answers(self):
        support.ENGINE_DB = os.path.join(self.td, 'none.db')
        self.assertEqual(support.read_sites(24, 10)['blocked'], [])
        self.assertEqual(support.read_events(5, False)['rows'], [])


class PollLoopTest(FirewallBase):
    def test_results_are_delivered_with_the_next_poll(self):
        sent = []
        queue = [[signed('overview')], []]

        def post(url, payload, token, timeout=20):
            sent.append((url, payload, token))
            return {'ok': True, 'commands': queue.pop(0) if queue else []}
        with mock.patch.object(support.time, 'sleep'), mock.patch.object(support, 'read_overview', return_value={'x': 1}):
            out = support.poll_loop(post, 'http://cloud:8080', FW, 'TOKEN', budget=0)
        self.assertTrue(out['ok'])
        self.assertEqual(sent[0][0], 'http://cloud:8080/api/v1/support/poll')
        self.assertEqual(sent[0][2], 'TOKEN')
        self.assertEqual(sent[0][1]['level'], 'manage')
        self.assertEqual(sent[1][1]['results'][0]['data'], {'x': 1})

    def test_results_survive_a_failed_post(self):
        support.write_private(support.PENDING, json.dumps([{'id': 'a' * 24, 'ok': True, 'message': 'kept'}]))
        calls = []

        def post(url, payload, token, timeout=20):
            calls.append(payload['results'])
            return {'ok': False, 'error': 'cannot reach'}
        out = support.poll_loop(post, 'http://x', FW, 'T', budget=0)
        self.assertFalse(out['ok'])
        self.assertEqual(calls[0][0]['message'], 'kept')
        self.assertEqual(support.load_pending()[0]['message'], 'kept')

    def test_a_command_that_fails_verification_still_gets_an_answer(self):
        bad = signed('overview', key=OTHER)
        seen = []

        def post(url, payload, token, timeout=20):
            seen.append(payload)
            return {'ok': True, 'commands': [bad] if len(seen) == 1 else []}
        with mock.patch.object(support.time, 'sleep'):
            support.poll_loop(post, 'http://x', FW, 'T', budget=0)
        self.assertFalse(seen[1]['results'][0]['ok'])
        self.assertIn('signature', seen[1]['results'][0]['message'])


if __name__ == '__main__':
    unittest.main()
