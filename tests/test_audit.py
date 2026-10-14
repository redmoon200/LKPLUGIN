#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Unit tests for the tamper-evident audit log (audit.py).
#   python3 -m unittest tests/test_audit.py

import importlib
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'security', 'layer7security', 'src',
                       'opnsense', 'scripts', 'OPNsense', 'Layer7Security')
sys.path.insert(0, SCRIPTS)

CONFIG = '''<opnsense><OPNsense><layer7security>
<audit><enabled>%s</enabled><retentionDays>%d</retentionDays><syslogLocal>0</syslogLocal><syslogTarget></syslogTarget></audit>
<users><user><name>alice</name><addresses>10.77.0.2,10.88.0.0/24</addresses></user></users>
</layer7security></OPNsense></opnsense>'''


class AuditCase(unittest.TestCase):
    enabled = '1'
    retention = 365

    def setUp(self):
        self.conns = []
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        t = self.tmp.name
        os.environ['L7_AUDIT_DB'] = os.path.join(t, 'audit.db')
        os.environ['L7_ENGINE_DB'] = os.path.join(t, 'l7.db')
        os.environ['L7_CONFIG'] = os.path.join(t, 'config.xml')
        os.environ['L7_AI_CATALOG'] = os.path.join(t, 'ai.json')
        with open(os.environ['L7_CONFIG'], 'w') as f:
            f.write(CONFIG % (self.enabled, self.retention))
        with open(os.environ['L7_AI_CATALOG'], 'w') as f:
            json.dump([{'id': 'claude', 'name': 'Claude / Anthropic', 'domains': ['claude.ai']}], f)
        import audit
        self.audit = importlib.reload(audit)

    def tearDown(self):
        for c in self.conns:
            c.close()
        self.tmp.cleanup()

    def db(self):
        con = sqlite3.connect(os.environ['L7_AUDIT_DB'])
        con.row_factory = sqlite3.Row
        self.conns.append(con)
        return con

    def fill(self, n=5):
        for i in range(n):
            self.audit.append('ai-use', 'observed', client='10.77.0.%d' % (i + 2), service='ChatGPT', host='chatgpt.com',
                              detail='note %d' % i)


class Chain(AuditCase):
    def test_chain_verifies_and_links(self):
        self.fill()
        res = self.audit.verify()
        self.assertTrue(res['ok'], res)
        self.assertEqual(res['records'], 5)
        rows = self.db().execute('SELECT seq, prev_hash, hash FROM audit ORDER BY seq').fetchall()
        self.assertEqual(rows[0]['prev_hash'], self.audit.GENESIS)
        for a, b in zip(rows, rows[1:]):
            self.assertEqual(b['prev_hash'], a['hash'])

    def test_editing_a_record_is_detected(self):
        self.fill()
        con = self.db()
        con.execute("UPDATE audit SET detail='nothing to see' WHERE seq=3")
        con.commit()
        res = self.audit.verify()
        self.assertFalse(res['ok'])
        self.assertEqual(res['bad_seq'], 3)
        self.assertIn('content', res['reason'])

    def test_deleting_a_middle_record_is_detected(self):
        self.fill()
        con = self.db()
        con.execute('DELETE FROM audit WHERE seq=3')
        con.commit()
        res = self.audit.verify()
        self.assertFalse(res['ok'])
        self.assertEqual(res['bad_seq'], 4)
        self.assertIn('gap', res['reason'])

    def test_deleting_the_tail_is_detected(self):
        self.fill()
        con = self.db()
        con.execute('DELETE FROM audit WHERE seq=5')
        con.commit()
        res = self.audit.verify()
        self.assertFalse(res['ok'])
        self.assertIn('missing', res['reason'])

    def test_rewriting_hash_without_the_followers_is_detected(self):
        self.fill()
        con = self.db()
        row = con.execute('SELECT * FROM audit WHERE seq=2').fetchone()
        rec = dict(row)
        rec['detail'] = 'forged'
        new = self.audit.chain_hash(row['prev_hash'], rec)
        con.execute("UPDATE audit SET detail='forged', hash=? WHERE seq=2", (new,))
        con.commit()
        res = self.audit.verify()
        self.assertFalse(res['ok'])
        self.assertEqual(res['bad_seq'], 3)
        self.assertIn('link', res['reason'])

    def test_empty_log_verifies(self):
        self.assertTrue(self.audit.verify()['ok'])


class Masking(AuditCase):
    def test_detail_is_masked_even_if_the_caller_forgets(self):
        card = '4111 1111 1111 1111'
        key = 'sk-ant-' + 'api03-' + 'aB3dE5gH7jK9mN1pQ3sT5v'
        self.audit.append('dlp-detect', 'observed', detail='user typed %s and %s here' % (card, key))
        detail = self.db().execute('SELECT detail FROM audit').fetchone()[0]
        self.assertNotIn('4111 1111 1111', detail)
        self.assertNotIn('aB3dE5', detail)

    def test_control_characters_and_length(self):
        self.audit.append('x', 'y', detail='a\r\nb\x00c' + 'z' * 1000)
        detail = self.db().execute('SELECT detail FROM audit').fetchone()[0]
        self.assertNotRegex(detail, '[\r\n\x00]')
        self.assertLessEqual(len(detail), self.audit.MAX_DETAIL)

    def test_disabled_logging_writes_nothing(self):
        with open(os.environ['L7_CONFIG'], 'w') as f:
            f.write(CONFIG % ('0', 365))
        self.assertIsNone(self.audit.append('ai-use', 'observed'))
        self.assertFalse(os.path.exists(os.environ['L7_AUDIT_DB']))


class Ingest(AuditCase):
    def engine_db(self, rows):
        con = sqlite3.connect(os.environ['L7_ENGINE_DB'])
        con.execute('CREATE TABLE events(id INTEGER PRIMARY KEY, ts INTEGER, type TEXT, client TEXT, server TEXT,'
                    ' app TEXT, category TEXT, host TEXT, policy TEXT, detail TEXT)')
        con.executemany('INSERT INTO events(ts,type,client,server,app,category,host,policy,detail) VALUES(?,?,?,?,?,?,?,?,?)', rows)
        con.commit()
        con.close()

    def test_ingest_maps_users_names_and_is_idempotent(self):
        now = int(time.time())
        self.engine_db([(now, 'ai-use', '10.77.0.2', '1.2.3.4', 'claude', 'AI', 'claude.ai', 'AI: Claude', 'monitored tcp/tls'),
                        (now, 'block', '10.77.0.2', '1.2.3.4', 'x', 'y', 'z', 'p', 'ignored'),
                        (now, 'ai-block', '10.88.0.9', '1.2.3.4', 'claude', 'AI', 'claude.ai', 'AI: Claude', 'blocked tcp/tls')])
        self.assertEqual(self.audit.ingest(), {'ingested': 0, 'enabled': True, 'initialised': True})   # history is skipped
        con = sqlite3.connect(os.environ['L7_ENGINE_DB'])
        con.execute("INSERT INTO events(ts,type,client,server,app,category,host,policy,detail) VALUES(?,?,?,?,?,?,?,?,?)",
                    (now, 'ai-use', '10.77.0.2', '1.2.3.4', 'claude', 'AI', 'claude.ai', 'AI: Claude', 'monitored tcp/tls'))
        con.execute("INSERT INTO events(ts,type,client,server,app,category,host,policy,detail) VALUES(?,?,?,?,?,?,?,?,?)",
                    (now, 'ai-block', '10.88.0.9', '1.2.3.4', 'claude', 'AI', 'claude.ai', 'AI: Claude', 'blocked tcp/tls'))
        con.execute("INSERT INTO events(ts,type,client,server,app,category,host,policy,detail) VALUES(?,?,?,?,?,?,?,?,?)",
                    (now, 'block', '10.77.0.2', '1.2.3.4', 'x', 'y', 'z', 'p', 'ignored'))
        con.commit()
        con.close()
        self.assertEqual(self.audit.ingest()['ingested'], 2)
        rows = self.db().execute('SELECT * FROM audit ORDER BY seq').fetchall()
        self.assertEqual([r['kind'] for r in rows], ['ai-use', 'ai-block'])
        self.assertEqual(rows[0]['user'], 'alice')
        self.assertEqual(rows[1]['user'], 'alice')          # 10.88.0.0/24 belongs to alice
        self.assertEqual(rows[0]['service'], 'Claude / Anthropic')
        self.assertEqual(rows[1]['action'], 'blocked')
        self.assertEqual(self.audit.ingest()['ingested'], 0)
        self.assertTrue(self.audit.verify()['ok'])

    def test_ingest_follows_an_engine_table_that_started_again(self):
        now = int(time.time())
        row = (now, 'ai-use', '10.77.0.2', '1.2.3.4', 'claude', 'AI', 'claude.ai', 'AI: Claude', 'monitored tcp/tls')
        self.engine_db([row] * 5)
        self.audit.ingest()                                   # initialised at event 5
        con = sqlite3.connect(os.environ['L7_ENGINE_DB'])
        con.execute('DELETE FROM events')                     # retention emptied the table: numbers start at 1 again
        con.executemany('INSERT INTO events(ts,type,client,server,app,category,host,policy,detail) VALUES(?,?,?,?,?,?,?,?,?)', [row] * 2)
        con.commit()
        con.close()
        self.assertEqual(self.audit.ingest()['ingested'], 2)
        self.assertEqual(self.audit.ingest()['ingested'], 0)
        self.assertTrue(self.audit.verify()['ok'])


class ExportAndRetention(AuditCase):
    def test_exports_are_verifiable_offline(self):
        self.fill()
        path = os.path.join(self.tmp.name, 'export.json')
        with open(path, 'w') as f:
            f.write(self.audit.export('json', 86400))
        self.assertTrue(self.audit.verify_file(path)['ok'])
        data = json.load(open(path))
        self.assertEqual(data['manifest']['records'], 5)
        self.assertEqual(data['manifest']['head_hash'], self.audit.verify()['head'])
        data['records'][2]['client'] = '9.9.9.9'
        json.dump(data, open(path, 'w'))
        self.assertFalse(self.audit.verify_file(path)['ok'])

    def test_jsonl_and_csv(self):
        self.fill(3)
        jl = self.audit.export('jsonl', 86400).strip().splitlines()
        self.assertEqual(len(jl), 3)
        cs = self.audit.export('csv', 86400).splitlines()
        self.assertTrue(cs[0].startswith('seq,ts,source,kind'))
        self.assertEqual(len(cs), 4)

    def test_csv_has_no_stray_padding(self):
        self.audit.append('x', 'y', client='', host='h')
        line = self.audit.export('csv', 86400).splitlines()[1]
        self.assertNotIn(chr(9), line)

    def test_csv_formula_injection_is_neutralised(self):
        self.audit.append('x', 'y', host='=HYPERLINK("http://evil")')
        self.assertNotIn(',=HYPERLINK', self.audit.export('csv', 86400))

    def test_prune_keeps_the_chain_verifiable(self):
        old = int(time.time()) - 400 * 86400
        for i in range(3):
            self.audit.append('ai-use', 'observed', ts=old + i, detail='old %d' % i)
        self.fill(2)
        self.assertEqual(self.audit.prune()['pruned'], 3)
        res = self.audit.verify()
        self.assertTrue(res['ok'], res)
        self.assertEqual(res['base_seq'], 3)
        kinds = [r['kind'] for r in self.db().execute('SELECT kind FROM audit ORDER BY seq')]
        self.assertEqual(kinds, ['ai-use', 'ai-use', 'audit-prune'])

    def test_listing_filters(self):
        self.fill(4)
        self.audit.append('dlp-detect', 'observed', client='10.77.0.9', detail='card ****')
        out = self.audit.listing(10, 0, 86400, 'dlp-detect', '-')
        self.assertEqual(out['total'], 1)
        out = self.audit.listing(2, 0, 86400, '-', '10.77.0.3')
        self.assertEqual(out['total'], 1)
        out = self.audit.listing(10, 0, 86400, '-', "x' OR 1=1 --")   # rejected phrase = no filter, never SQL
        self.assertEqual(out['total'], 5)


class Access(AuditCase):
    def test_access_to_the_log_is_itself_logged(self):
        with open(os.environ['L7_CONFIG'], 'w') as f:
            f.write(CONFIG % ('0', 365))      # even with auditing off, access is recorded
        self.audit.access('admin<script>', 'export')
        row = self.db().execute('SELECT * FROM audit').fetchone()
        self.assertEqual((row['kind'], row['action'], row['user']), ('audit-access', 'export', 'adminscript'))


if __name__ == '__main__':
    unittest.main()
