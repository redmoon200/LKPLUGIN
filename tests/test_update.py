#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Unit tests for the firewall side of the update channel (update.py): what makes a signed update list and a package trustworthy, check, install
# with rollback, the OPNsense firmware status and the remote support actions that start updates. Lists are signed with a throw-away key
# (tests/vendor_sign.py).
#   python -m unittest tests/test_update.py

import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
SCRIPTS = os.path.join(ROOT, 'security', 'layer7security', 'src', 'opnsense', 'scripts', 'OPNsense', 'Layer7Security')
sys.path.insert(0, SCRIPTS)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_TMP = tempfile.mkdtemp(prefix='l7upd-')
os.environ['L7_BASE'] = os.path.join(_TMP, 'fwbase')
_KEYDIR = tempfile.mkdtemp(prefix='l7updkey-')
PRIV = os.path.join(_KEYDIR, 'vendor.pem')
OTHER = os.path.join(_KEYDIR, 'other.pem')

import vendor_sign  # noqa: E402

PUB_PEM = vendor_sign.generate_keypair(PRIV)
vendor_sign.generate_keypair(OTHER)

import support  # noqa: E402
import update  # noqa: E402

FW = '1234-ABCD-5678-EF01'


def need_level(action):
    return 'view' if action in support.READ else 'manage'


def make_pkg(version, name='os-layer7security', pad=20000):
    """a small gzip-compressed tar with a +MANIFEST, standing in for a package"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        manifest = json.dumps({'name': name, 'version': version}).encode()
        for fname, data in (('+MANIFEST', manifest), ('payload', os.urandom(pad))):
            info = tarfile.TarInfo(fname)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()




def use_vendor_key(case):
    """this file's test key, trusted on the firewall side, for one test"""
    for p in (mock.patch.object(support, 'public_pem', return_value=PUB_PEM), mock.patch.object(support, 'OPENSSL', vendor_sign.OPENSSL)):
        p.start()
        case.addCleanup(p.stop)



class FirewallBase(unittest.TestCase):
    def setUp(self):
        use_vendor_key(self)
        self.td = tempfile.mkdtemp(prefix='l7fwu-')
        for name, rel in (('STATE', 'update.json'), ('LOG', 'update.log'), ('LOCK', 'update.lock'), ('UPDATE_DIR', 'updates'), ('ROLLBACK_DIR', 'rollback')):
            setattr(update, name, os.path.join(self.td, rel))
        for name, rel in (('AUDIT', 'a.jsonl'), ('SEEN', 's.json'), ('PENDING', 'p.json')):
            setattr(support, name, os.path.join(self.td, rel))
        self.cfg = {'general': {'enabled': '1', 'feedUrl': 'http://cloud:8080/feeds'}}
        for p in (mock.patch.object(update.cloudlib, 'settings', side_effect=lambda: self.cfg), mock.patch.object(update, 'opnsense_version', return_value='26.1.11')):
            p.start()
            self.addCleanup(p.stop)



def signed_manifest(entries, issued=None, key=PRIV, **over):
    body = {'v': 1, 'product': 'os-layer7security', 'issued': issued or int(time.time()), 'channels': entries}
    body.update(over)
    sig = vendor_sign.sign_manifest(body, key)
    return dict(body, sig=sig)


def entry(version='0.6.0', data=None, **over):
    data = data if data is not None else make_pkg(version)
    e = {'version': version, 'file': 'os-layer7security-%s.pkg' % version, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'notes': 'What is new', 'released': int(time.time()),
         'min_opnsense': ''}
    e.update(over)
    return e



class ManifestTest(FirewallBase):
    def test_signed_manifest_is_accepted(self):
        self.assertEqual(update.verify_manifest(signed_manifest({'stable': entry()})), (True, ''))

    def test_tampering_and_wrong_keys_are_refused(self):
        doc = signed_manifest({'stable': entry()})
        for change in ({'issued': doc['issued'] + 1}, {'channels': {'stable': entry('9.9.9')}}, {'product': 'other'}, {'v': 2}):
            bad = dict(doc, **change)
            self.assertFalse(update.verify_manifest(bad)[0], change)
        self.assertFalse(update.verify_manifest(signed_manifest({'stable': entry()}, key=OTHER))[0])
        for junk in (None, {}, {'sig': 'x'}, {'sig': 'AAAA'}, 'x'):
            self.assertFalse(update.verify_manifest(junk)[0])

    def test_a_support_command_signature_is_not_a_manifest(self):
        body = {'v': 1, 'product': 'os-layer7security', 'issued': 5, 'channels': {}}
        msg = json.dumps(body, sort_keys=True, separators=(',', ':')).encode()
        import base64
        sig = base64.b64encode(vendor_sign.sign_message(msg, PRIV, vendor_sign.COMMAND_DOMAIN)).decode()               # signed with the command prefix
        self.assertFalse(update.verify_manifest(dict(body, sig=sig))[0])

    def test_entries_are_strict(self):
        self.assertIsNotNone(update.clean_entry(entry()))
        for bad in (entry(version='../../x'), entry(file='evil.pkg'), entry(sha256='zz'), entry(size=5), entry(size=10 ** 9), entry(size='x'), 'x', None,
                    entry(file='os-layer7security-0.6.1.pkg')):
            self.assertIsNone(update.clean_entry(bad), bad)


class CheckTest(FirewallBase):
    def check_with(self, doc, installed='0.5.0'):
        with mock.patch.object(update, 'http_get', return_value=json.dumps(doc).encode()), mock.patch.object(update, 'installed_version', return_value=installed):
            return update.check()

    def test_a_newer_release_is_found(self):
        st = self.check_with(signed_manifest({'stable': entry('0.6.0')}))
        self.assertEqual((st['latest'], st['available'], st['error']), ('0.6.0', True, ''))
        self.assertEqual(st['notes'], 'What is new')

    def test_same_or_older_is_not_an_update(self):
        self.assertFalse(self.check_with(signed_manifest({'stable': entry('0.5.0')}))['available'])
        self.assertFalse(self.check_with(signed_manifest({'stable': entry('0.4.0')}))['available'])

    def test_channel_choice(self):
        doc = signed_manifest({'stable': entry('0.6.0'), 'beta': entry('0.7.0')})
        self.assertEqual(self.check_with(doc)['latest'], '0.6.0')
        self.cfg['general']['updateChannel'] = 'beta'
        self.assertEqual(self.check_with(doc)['latest'], '0.7.0')
        self.assertEqual(self.check_with(signed_manifest({'stable': entry('0.6.0')}))['latest'], '0.6.0')   # no beta entry: stable

    def test_an_old_manifest_is_refused_after_a_newer_one(self):
        now = int(time.time())
        self.check_with(signed_manifest({'stable': entry('0.6.0')}, issued=now))
        st = self.check_with(signed_manifest({'stable': entry('0.5.5')}, issued=now - 1000))
        self.assertIn('older', st['error'])
        self.assertEqual(update.read_state()['latest'], '0.6.0')                      # what was known stays

    def test_a_failed_update_is_forgotten_when_the_release_is_replaced(self):
        update.write_state({'state': 'failed', 'error': 'x', 'target': '9.9.9'})
        st = self.check_with(signed_manifest({'stable': entry('0.6.0')}))                  # 9.9.9 was withdrawn, 0.6.0 is the answer now
        self.assertEqual((st['state'], st['error']), ('idle', ''))
        update.write_state({'state': 'failed', 'error': 'x', 'target': '0.6.0'})
        self.assertEqual(self.check_with(signed_manifest({'stable': entry('0.6.0')}))['state'], 'failed')      # the same release still failed

    def test_unsigned_and_foreign_manifests_are_refused(self):
        st = self.check_with(signed_manifest({'stable': entry()}, key=OTHER))
        self.assertIn('Refused', st['error'])
        self.assertFalse(st.get('available'))

    def test_minimum_opnsense_blocks_the_update(self):
        st = self.check_with(signed_manifest({'stable': entry('0.6.0', min_opnsense='26.7')}))
        self.assertFalse(st['available'])
        self.assertIn('needs OPNsense 26.7', st['blocked'])

    def test_unreachable_server_and_no_address(self):
        with mock.patch.object(update, 'http_get', side_effect=OSError('down')), mock.patch.object(update, 'installed_version', return_value='0.5.0'):
            self.assertIn('cannot reach', update.check()['error'])
        self.cfg['general']['feedUrl'] = ''
        self.assertIn('address', update.check()['error'])


class InstallTest(FirewallBase):
    def prepare(self, version='0.6.0', installed='0.5.0'):
        self.data = make_pkg(version)
        self.entry = entry(version, self.data)
        update.write_state({'available': True, 'latest': version, 'entry': self.entry, 'installed': installed})
        self.versions = [installed]

        def fake_get(url, limit, timeout=60):
            return self.data
        self.identity = ('os-layer7security', version)
        self.patches = [mock.patch.object(update, 'http_get', side_effect=fake_get), mock.patch.object(update, 'after_install'),
                        mock.patch.object(update, 'package_identity', side_effect=lambda path: self.identity),
                        mock.patch.object(update, 'installed_version', side_effect=lambda: self.versions[-1]), mock.patch.object(update.time, 'sleep')]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_successful_update(self):
        self.prepare()
        added = []

        def pkg_add(path):
            added.append(os.path.basename(path))
            self.versions.append('0.6.0')
            return True, ''
        with mock.patch.object(update, 'pkg_add', side_effect=pkg_add), mock.patch.object(update, 'make_rollback_copy', return_value='/x/os-layer7security-0.5.0.pkg'), \
                mock.patch.object(update, 'healthy', return_value=(True, '')):
            res = update.install()
        self.assertTrue(res['ok'])
        self.assertEqual(added, ['os-layer7security-0.6.0.pkg'])
        st = update.read_state()
        self.assertEqual((st['state'], st['installed'], st['rollback'], st['available']), ('idle', '0.6.0', '0.5.0', False))
        self.assertFalse(os.path.exists(update.LOCK))

    def test_a_package_that_does_not_match_the_signed_checksum_is_never_installed(self):
        self.prepare()
        tampered = bytearray(self.data)
        tampered[-5] ^= 0xFF
        self.data = bytes(tampered)                                        # same size, one byte different from what was signed
        with mock.patch.object(update, 'pkg_add') as add:
            res = update.install()
        add.assert_not_called()
        self.assertFalse(res['ok'])
        self.assertIn('signed checksum', res['message'])
        self.assertEqual(update.read_state()['state'], 'failed')

    def test_a_package_that_is_not_what_the_manifest_says_changes_nothing(self):
        """the signed manifest says 0.6.0, the file inside says 0.5.0 (or is something else): refused before any change"""
        for ident in (('os-layer7security', '0.5.0'), ('os-other', '0.6.0'), None):
            self.prepare()
            self.identity = ident
            with mock.patch.object(update, 'pkg_add') as add, mock.patch.object(update, 'make_rollback_copy') as copy:
                res = update.install()
            add.assert_not_called()
            copy.assert_not_called()
            self.assertFalse(res['ok'])
            self.assertIn('nothing was changed', update.read_state()['error'])

    def test_wrong_size_is_refused(self):
        self.prepare()
        self.data = self.data + b'extra'
        with mock.patch.object(update, 'pkg_add') as add:
            res = update.install()
        add.assert_not_called()
        self.assertFalse(res['ok'])

    def test_failed_health_check_rolls_back(self):
        self.prepare()
        calls = []

        def pkg_add(path):
            calls.append(os.path.basename(path))
            self.versions.append('0.6.0' if 'rollback' not in path and '0.6.0' in path else '0.5.0')
            return True, ''
        results = iter([(False, 'the engine is not running'), (True, '')])
        with mock.patch.object(update, 'pkg_add', side_effect=pkg_add), mock.patch.object(update, 'make_rollback_copy', return_value=os.path.join(self.td, 'os-layer7security-0.5.0.pkg')), \
                mock.patch.object(update, 'healthy', side_effect=lambda v: next(results)):
            res = update.install()
        self.assertFalse(res['ok'])
        self.assertIn('previous version was restored', res['message'])
        self.assertEqual(calls, ['os-layer7security-0.6.0.pkg', 'os-layer7security-0.5.0.pkg'])
        st = update.read_state()
        self.assertEqual(st['state'], 'failed')
        self.assertIn('Rolled back to 0.5.0', st['error'])

    def test_a_failed_rollback_says_so(self):
        self.prepare()
        with mock.patch.object(update, 'pkg_add', return_value=(True, '')), mock.patch.object(update, 'make_rollback_copy', return_value=os.path.join(self.td, 'b.pkg')), \
                mock.patch.object(update, 'healthy', return_value=(False, 'broken')):
            res = update.install()
        self.assertIn('restoring it failed too', res['message'])
        self.assertIn('repair needed', update.read_state()['error'])

    def test_no_rollback_copy_means_no_change(self):
        self.prepare()
        with mock.patch.object(update, 'pkg_add') as add, mock.patch.object(update, 'make_rollback_copy', return_value=None):
            res = update.install()
        add.assert_not_called()
        self.assertFalse(res['ok'])
        self.assertIn('nothing was changed', update.read_state()['error'])

    def test_nothing_older_or_equal_is_installed(self):
        self.prepare('0.5.0', installed='0.5.0')
        with mock.patch.object(update, 'pkg_add') as add:
            self.assertFalse(update.install()['ok'])
        add.assert_not_called()
        self.prepare('0.4.0', installed='0.5.0')
        with mock.patch.object(update, 'pkg_add') as add:
            self.assertFalse(update.install()['ok'])
        add.assert_not_called()

    def test_only_one_update_at_a_time(self):
        self.prepare()
        self.assertTrue(update.lock())
        try:
            with mock.patch.object(update, 'pkg_add') as add:
                res = update.install()
            add.assert_not_called()
            self.assertIn('already running', res['message'])
        finally:
            update.unlock()

    def test_rollback_goes_to_the_older_copy(self):
        os.makedirs(update.ROLLBACK_DIR)
        for v, age in (('0.5.0', 100), ('0.6.0', 0)):
            p = os.path.join(update.ROLLBACK_DIR, 'os-layer7security-%s.pkg' % v)
            with open(p, 'wb') as f:
                f.write(b'x')
            os.utime(p, (time.time() - age, time.time() - age))
        versions = ['0.6.0']
        added = []

        def pkg_add(path):
            added.append(os.path.basename(path))
            versions.append('0.5.0')
            return True, ''
        with mock.patch.object(update, 'installed_version', side_effect=lambda: versions[-1]), mock.patch.object(update, 'pkg_add', side_effect=pkg_add), \
                mock.patch.object(update, 'after_install'), mock.patch.object(update, 'healthy', return_value=(True, '')), mock.patch.object(update, 'check') as checked:
            res = update.rollback()
        self.assertTrue(res['ok'])
        self.assertEqual(added, ['os-layer7security-0.5.0.pkg'])
        self.assertEqual(update.read_state()['installed'], '0.5.0')
        checked.assert_called_once()                                       # the release we left is offered again

    def test_the_gui_rollback_is_detached_and_refuses_when_there_is_nothing_to_go_back_to(self):
        with mock.patch.object(update, 'installed_version', return_value='0.6.0'), mock.patch.object(update.subprocess, 'Popen') as popen:
            self.assertIn('no earlier version', update.rollback_async()['message'])
            popen.assert_not_called()
            os.makedirs(update.ROLLBACK_DIR)
            for v in ('0.5.0', '0.6.0'):
                with open(os.path.join(update.ROLLBACK_DIR, 'os-layer7security-%s.pkg' % v), 'wb') as f:
                    f.write(b'x')
            res = update.rollback_async()
        self.assertTrue(res['started'])
        self.assertEqual(popen.call_args[0][0][-1], 'rollback')
        self.assertTrue(popen.call_args[1]['start_new_session'])
        self.assertEqual(update.read_state()['state'], 'installing')

    def test_rollback_without_a_copy(self):
        with mock.patch.object(update, 'installed_version', return_value='0.6.0'):
            self.assertIn('no earlier version', update.rollback()['message'])

    def test_automatic_updates_only_when_switched_on(self):
        doc = signed_manifest({'stable': entry('0.6.0')})
        with mock.patch.object(update, 'http_get', return_value=json.dumps(doc).encode()), mock.patch.object(update, 'installed_version', return_value='0.5.0'), \
                mock.patch.object(update, 'firmware_check'), mock.patch.object(update, 'install', return_value={'ok': True}) as inst:
            update.auto()
            inst.assert_not_called()
            self.cfg['general']['autoUpdate'] = '1'
            update.auto()
            inst.assert_called_once()


class FirmwareTest(FirewallBase):
    SAMPLE = {'api_version': '2', 'connection': 'ok', 'last_check': 'Sun Nov  8 06:24:34 UTC 2026', 'needs_reboot': '0', 'new_packages': [], 'product_version': '26.1.11_10',
              'product_abi': '26.1', 'download_size': '7MiB', 'repository': 'ok', 'upgrade_major_version': '26.7',
              'upgrade_major_message': '<p>OPNsense 26.1 "<em>Witty Woodpecker</em>" has reached its end of life. As such it will not receive any more updates.</p>',
              'upgrade_packages': [{'name': 'php83', 'repository': 'OPNsense', 'current_version': '8.3.31', 'new_version': '8.3.36'},
                                   {'name': 'php83-zlib', 'repository': 'OPNsense', 'current_version': '8.3.31', 'new_version': '8.3.36'}]}

    def write(self, d):
        path = os.path.join(self.td, 'pkg_upgrade.json')
        with open(path, 'w') as f:
            json.dump(d, f)
        p = mock.patch.object(update, 'FIRMWARE_JSON', path)
        p.start()
        self.addCleanup(p.stop)

    def test_status_is_read_from_the_file_opnsense_writes(self):
        self.write(self.SAMPLE)
        with mock.patch.object(update, 'firmware_busy', return_value=False):
            st = update.firmware_status()
        self.assertEqual((st['patch_count'], st['version'], st['needs_reboot']), (2, '26.1.11_10', False))
        self.assertEqual(st['patches'][0], {'name': 'php83', 'from': '8.3.31', 'to': '8.3.36'})
        self.assertEqual((st['major']['version'], st['major']['eol']), ('26.7', True))
        self.assertNotIn('<', st['major']['note'])
        self.assertGreater(st['checked'], 1700000000)

    def test_clean_system(self):
        d = dict(self.SAMPLE, upgrade_packages=[], upgrade_major_version='', needs_reboot='1')
        self.write(d)
        with mock.patch.object(update, 'firmware_busy', return_value=False):
            st = update.firmware_status()
        self.assertEqual((st['patch_count'], st['major'], st['needs_reboot']), (0, None, True))

    def test_missing_or_broken_file(self):
        with mock.patch.object(update, 'FIRMWARE_JSON', os.path.join(self.td, 'none.json')), mock.patch.object(update, 'firmware_busy', return_value=False):
            self.assertEqual(update.firmware_status()['checked'], 0)
        bad = os.path.join(self.td, 'bad.json')
        with open(bad, 'w') as f:
            f.write('{broken')
        with mock.patch.object(update, 'FIRMWARE_JSON', bad), mock.patch.object(update, 'firmware_busy', return_value=False):
            self.assertEqual(update.firmware_status()['patch_count'], 0)

    def test_a_firmware_check_already_running_is_waited_for_not_started_again(self):
        self.write(self.SAMPLE)
        busy = iter([True, True, False])
        with mock.patch.object(update, 'firmware_busy', side_effect=lambda: next(busy, False)), mock.patch.object(update, 'run') as run, mock.patch.object(update.time, 'sleep'):
            update.firmware_check(30)
        run.assert_not_called()

    def test_firmware_update_needs_a_check_with_something_to_do_and_a_quiet_system(self):
        self.write(dict(self.SAMPLE, upgrade_packages=[]))
        with mock.patch.object(update, 'firmware_busy', return_value=False), mock.patch.object(update.subprocess, 'Popen') as popen:
            self.assertIn('no updates waiting', update.firmware_update()['message'])
            popen.assert_not_called()
        self.write(self.SAMPLE)
        with mock.patch.object(update, 'firmware_busy', return_value=True), mock.patch.object(update.subprocess, 'Popen') as popen:
            self.assertIn('busy', update.firmware_update()['message'])
            popen.assert_not_called()
        with mock.patch.object(update, 'firmware_busy', return_value=False), mock.patch.object(update.subprocess, 'Popen') as popen:
            res = update.firmware_update()
        self.assertTrue(res['ok'])
        self.assertEqual(popen.call_args[0][0], [update.CONFIGCTL, 'firmware', 'update'])           # the minor update, never "upgrade" and never a reboot

    def test_summary_is_what_the_report_carries(self):
        self.write(self.SAMPLE)
        update.write_state({'installed': '0.5.0', 'latest': '0.6.0', 'available': True, 'channel': 'stable', 'checked': 5, 'state': 'idle'})
        s = update.summary()
        self.assertEqual((s['plugin']['installed'], s['plugin']['available'], s['firmware']['patch_count']), ('0.5.0', True, 2))
        self.assertEqual((s['plugin']['latest'], s['firmware']['major']['eol']), ('0.6.0', True))


class RemoteActionsTest(FirewallBase):
    def setUp(self):
        super().setUp()
        self.cfg['general']['remoteSupport'] = 'manage'

    def run_cmd(self, action):
        env = vendor_sign.command_envelope(os.urandom(12).hex(), FW, action, {}, need_level(action), int(time.time()), int(time.time()) + 600, PRIV)
        return support.execute(env, FW)

    def test_levels(self):
        self.assertEqual(need_level('updates'), 'view')
        for a in ('plugin_update', 'firmware_check', 'firmware_update'):
            self.assertEqual(need_level(a), 'manage')
        self.assertTrue({'plugin_update', 'firmware_check', 'firmware_update'} <= support.WRITE and 'updates' in support.READ)

    def test_view_can_read_update_status_but_not_start_anything(self):
        self.cfg['general']['remoteSupport'] = 'view'
        with mock.patch.object(update, 'status', return_value={'plugin': {}}):
            self.assertTrue(self.run_cmd('updates')['ok'])
        with mock.patch.object(update, 'install_async') as inst:
            res = self.run_cmd('plugin_update')
        inst.assert_not_called()
        self.assertIn('only allows viewing', res['message'])

    def test_manage_starts_the_actions(self):
        with mock.patch.object(update, 'install_async', return_value={'ok': True, 'message': 'Updating to 0.6.0.'}) as a:
            self.assertTrue(self.run_cmd('plugin_update')['ok'])
        a.assert_called_once()
        with mock.patch.object(update, 'start_detached') as d:
            self.assertTrue(self.run_cmd('firmware_check')['ok'])
        d.assert_called_once_with('firmware-check')
        with mock.patch.object(update, 'firmware_update', return_value={'ok': True, 'message': 'Updating 2 package(s).'}):
            self.assertTrue(self.run_cmd('firmware_update')['ok'])

    def test_off_refuses_them_all(self):
        self.cfg['general']['remoteSupport'] = 'off'
        for a in ('updates', 'plugin_update', 'firmware_check', 'firmware_update'):
            self.assertFalse(self.run_cmd(a)['ok'], a)


if __name__ == '__main__':
    unittest.main()
