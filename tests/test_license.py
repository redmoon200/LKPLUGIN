#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Unit tests for the license keys and the cloud server's license logic (needs the openssl command, OpenSSL 3).
#   python -m unittest tests/test_license.py

import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
STATE = tempfile.mkdtemp(prefix='l7lic')
os.environ['L7_CLOUD_ROOT'] = STATE
sys.path.insert(0, os.path.join(ROOT, 'cloud', 'server'))

import cloudcore  # noqa: E402
import licenselib  # noqa: E402
import store  # noqa: E402

INSTALL = '1234-ABCD-5678-EF01'
OTHER = '9999-AAAA-0000-1111'
DAY = 86400


class KeyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv = os.path.join(STATE, 'k', 'signing.pem')
        cls.pub = licenselib.generate_keypair(cls.priv)

    def test_round_trip_for_every_type(self):
        now = int(time.time())
        for kind, days in (('trial', 30), ('year', 365), ('lifetime', 0)):
            info = licenselib.issue(kind, self.priv, issued_ts=now)
            got = licenselib.parse(info['key'], self.pub)
            self.assertTrue(got['ok'], got)
            self.assertEqual(got['type'], kind)
            self.assertEqual(got['days'], days)
            self.assertEqual(got['key_id'], info['key_id'])
            self.assertFalse(got['bound'])
            if kind == 'lifetime':
                self.assertIsNone(got['expires'])
            else:
                self.assertEqual(got['expires'] - got['issued'], days * DAY)

    def test_text_form(self):
        key = licenselib.issue('year', self.priv)['key']
        groups = key.split('-')
        self.assertTrue(all(len(g) == 5 for g in groups[:-1]))
        self.assertTrue(licenselib.parse(key.lower().replace('-', ' '), self.pub)['ok'])

    def test_binding(self):
        info = licenselib.issue('year', self.priv, INSTALL)
        self.assertTrue(info['bound'])
        self.assertEqual(info['bind'], licenselib.bind_hash(INSTALL).hex())
        self.assertNotEqual(info['bind'], licenselib.bind_hash(OTHER).hex())
        with self.assertRaises(ValueError):
            licenselib.issue('year', self.priv, 'not-an-id')

    def test_tampered_or_foreign_keys_are_refused(self):
        key = licenselib.issue('trial', self.priv)['key']
        raw = bytearray(licenselib.b32_decode(licenselib.normalize(key)))
        raw[1] = 4                                   # trial -> lifetime
        forged = licenselib.group(bytes(raw))
        self.assertFalse(licenselib.parse(forged, self.pub)['ok'])
        other_priv = os.path.join(STATE, 'k2', 'signing.pem')
        other_pub = licenselib.generate_keypair(other_priv)
        self.assertFalse(licenselib.parse(key, other_pub)['ok'])
        self.assertFalse(licenselib.parse('ABCDE-FGHIJ', self.pub)['ok'])
        self.assertFalse(licenselib.parse('', self.pub)['ok'])

    def test_every_key_id_is_new(self):
        ids = {licenselib.issue('trial', self.priv)['key_id'] for _ in range(5)}
        self.assertEqual(len(ids), 5)

    def test_public_key_is_32_bytes(self):
        self.assertEqual(len(__import__('base64').b64decode(licenselib.public_b64(self.pub))), 32)


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.makedirs(cloudcore.LICENSE_DIR, exist_ok=True)
        cloudcore.ensure_keys()

    def setUp(self):
        self.con = store.connect()

    def tearDown(self):
        self.con.close()

    def test_password_hash(self):
        h = store.hash_password('correct horse battery')
        self.assertTrue(store.check_password('correct horse battery', h))
        self.assertFalse(store.check_password('wrong', h))
        self.assertFalse(store.check_password('x', ''))
        self.assertNotEqual(h, store.hash_password('correct horse battery'))

    def test_issue_and_list(self):
        info = cloudcore.issue_license(self.con, 'year', 'Acme', 'note', INSTALL)
        row = cloudcore.license_row(self.con, info['key_id'])
        self.assertEqual(row['customer'], 'Acme')
        self.assertEqual(row['bound_install'], INSTALL)
        self.assertEqual(cloudcore.row_state(row), 'active')
        with self.assertRaises(ValueError):
            cloudcore.issue_license(self.con, 'forever', 'x')
        with self.assertRaises(ValueError):
            cloudcore.issue_license(self.con, 'year', 'x', install_id='bad')

    def test_backdated_license_is_expired(self):
        info = cloudcore.issue_license(self.con, 'year', 'Old', issued_ts=int(time.time()) - 400 * DAY)
        self.assertEqual(cloudcore.row_state(cloudcore.license_row(self.con, info['key_id'])), 'expired')

    def test_checkin_states(self):
        inst = 'AAAA-BBBB-CCCC-0001'
        res = cloudcore.checkin(self.con, '10.0.0.1', {'install_id': inst, 'version': '0.5.0', 'hostname': 'fw1'})
        self.assertTrue(res['ok'])
        self.assertEqual(res['license']['state'], 'none')
        info = cloudcore.issue_license(self.con, 'year', 'Checkin', install_id=inst)
        res = cloudcore.checkin(self.con, '10.0.0.1', {'install_id': inst, 'key': info['key']})
        self.assertEqual(res['license']['state'], 'active')
        cloudcore.set_revoked(self.con, info['key_id'], True)
        res = cloudcore.checkin(self.con, '10.0.0.1', {'install_id': inst, 'key': info['key']})
        self.assertEqual(res['license']['state'], 'revoked')
        cloudcore.set_revoked(self.con, info['key_id'], False)
        self.assertEqual(cloudcore.checkin(self.con, '10.0.0.1', {'install_id': inst, 'key': info['key']})['license']['state'], 'active')
        res = cloudcore.checkin(self.con, '10.0.0.1', {'install_id': inst, 'key': 'ABCDE-FGHIJ'})
        self.assertEqual(res['license']['state'], 'invalid')
        self.assertFalse(cloudcore.checkin(self.con, '10.0.0.1', {'install_id': 'nope'})['ok'])
        rows = cloudcore.clients(self.con)
        mine = [r for r in rows if r['install_id'] == inst][0]
        self.assertEqual(mine['hostname'], 'fw1')
        self.assertGreaterEqual(mine['checkins'], 4)

    def test_replacement_is_offered_at_checkin(self):
        inst = 'AAAA-BBBB-CCCC-0002'
        old = cloudcore.issue_license(self.con, 'year', 'Renew', install_id=inst)
        new = cloudcore.replace_license(self.con, old['key_id'], 'lifetime')
        res = cloudcore.checkin(self.con, '10.0.0.2', {'install_id': inst, 'key': old['key']})
        self.assertEqual(res.get('update_key'), new['key'])
        res = cloudcore.checkin(self.con, '10.0.0.2', {'install_id': inst, 'key': new['key']})
        self.assertNotIn('update_key', res)

    def test_trial_once_per_firewall(self):
        inst = 'AAAA-BBBB-CCCC-0003'
        first = cloudcore.trial(self.con, '10.0.0.3', {'install_id': inst, 'hostname': 'fw3'})
        self.assertTrue(first['ok'])
        self.assertEqual(licenselib.parse(first['key'], cloudcore.public_pem())['type'], 'trial')
        again = cloudcore.trial(self.con, '10.0.0.3', {'install_id': inst})
        self.assertTrue(again['ok'])
        self.assertEqual(again['key'], first['key'])
        key_id = licenselib.parse(first['key'], cloudcore.public_pem())['key_id']
        cloudcore.set_revoked(self.con, key_id, True)
        self.assertFalse(cloudcore.trial(self.con, '10.0.0.3', {'install_id': inst})['ok'])
        store.set_setting(self.con, 'trials_enabled', '0')
        self.assertFalse(cloudcore.trial(self.con, '10.0.0.4', {'install_id': 'AAAA-BBBB-CCCC-0004'})['ok'])
        store.set_setting(self.con, 'trials_enabled', '1')
        self.assertFalse(cloudcore.trial(self.con, '10.0.0.4', {'install_id': 'bad'})['ok'])

    def test_unknown_signed_key_is_recorded(self):
        info = licenselib.issue('year', cloudcore.PRIVATE_PEM)
        res = cloudcore.checkin(self.con, '10.0.0.5', {'install_id': 'AAAA-BBBB-CCCC-0005', 'key': info['key']})
        self.assertEqual(res['license']['state'], 'active')
        self.assertIsNotNone(cloudcore.license_row(self.con, info['key_id']))


if __name__ == '__main__':
    unittest.main()
