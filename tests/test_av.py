#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Tests of the download protection (file types, hash reputation, the /av ICAP service).
#   python3 -m unittest tests/test_av.py

import asyncio
import gzip
import hashlib
import importlib
import json
import os
import sys
import tempfile
import unittest

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'security', 'layer7security', 'src',
                       'opnsense', 'scripts', 'OPNsense', 'Layer7Security')
sys.path.insert(0, SCRIPTS)

EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
PE = b'MZ' + b'\x90\x00' * 40


def respmod(body, url='http://dl.example.com/files/setup.bin?token=SECRET', status='200 OK', headers='', chunks=None):
    req = ('GET %s HTTP/1.1\r\nHost: dl.example.com\r\n\r\n' % url).encode()
    res = ('HTTP/1.1 %s\r\nContent-Type: application/octet-stream\r\n%sContent-Length: %d\r\n\r\n'
           % (status, headers, len(body))).encode()
    icap = ('RESPMOD icap://127.0.0.1:1344/av ICAP/1.0\r\nHost: 127.0.0.1\r\nAllow: 204\r\nX-Client-IP: 10.77.0.2\r\n'
            'Encapsulated: req-hdr=0, res-hdr=%d, res-body=%d\r\n\r\n' % (len(req), len(req) + len(res))).encode()
    out = icap + req + res
    for piece in (chunks or [body]):
        out += ('%x\r\n' % len(piece)).encode() + piece + b'\r\n'
    return out + b'0\r\n\r\n'


async def exchange(port, payload):
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    writer.write(payload)
    await writer.drain()
    head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
    status = int(head.split(b' ', 2)[1])
    rest = b''
    if status == 200 and b'res-hdr' in head:
        rest = await asyncio.wait_for(reader.read(65536), 5)
    writer.close()
    return status, head.decode('latin-1'), rest


class AvCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        t = self.tmp.name
        os.environ.update({'L7_AUDIT_DB': os.path.join(t, 'audit.db'), 'L7_CONFIG': os.path.join(t, 'config.xml'),
                           'L7_INSPECTION_JSON': os.path.join(t, 'inspection.json'),
                           'L7_AI_CATALOG': os.path.join(t, 'ai.json'), 'L7_ICAP_STATS': os.path.join(t, 's.json')})
        import avscan
        import icap_server
        self.av = avscan
        self.av.AV_DB = os.path.join(t, 'av.db')
        self.av.HASH_FILE = os.path.join(t, 'hashes.txt')
        self.av.FEED_INFO = os.path.join(t, 'feed.json')
        self.av.hash_state.update(mtime=None, custom=None, checked=0)
        self.av.hashes.clear()
        self.icap = importlib.reload(icap_server)
        self.configure({})
        self.server = await asyncio.start_server(self.icap.serve_client, '127.0.0.1', 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self.tmp.cleanup()

    def configure(self, av):
        base = {'enabled': True, 'hashAction': 'block', 'types': {'executable': 'monitor', 'script': 'monitor',
                                                                   'package': 'monitor', 'archive': 'off'}}
        base.update(av)
        self.av.configure(base)
        self.av.hash_state['custom'] = None

    def events(self):
        return self.av.listing(100, 0, 86400, '')['rows']


class FileTypes(unittest.TestCase):
    def setUp(self):
        import avscan
        self.av = avscan

    def test_magic_beats_the_name(self):
        self.assertEqual(self.av.classify(PE, 'holiday.jpg')[0], 'executable')
        self.assertEqual(self.av.classify(b'\x7fELF\x02\x01', 'x')[0], 'executable')
        self.assertEqual(self.av.classify(b'#!/bin/sh\necho hi', 'readme.txt')[0], 'script')

    def test_zip_family(self):
        zip_head = b'PK\x03\x04' + b'\x00' * 30
        self.assertEqual(self.av.classify(zip_head, 'data.zip')[0], 'archive')
        self.assertEqual(self.av.classify(zip_head, 'app.apk')[0], 'package')
        self.assertEqual(self.av.classify(zip_head, 'report.docx')[0], None)

    def test_java_class_vs_fat_binary(self):
        self.assertEqual(self.av.classify(b'\xca\xfe\xba\xbe\x00\x00\x00\x34', 'A')[0], 'package')
        self.assertEqual(self.av.classify(b'\xca\xfe\xba\xbe\x00\x00\x00\x02', 'a')[0], 'executable')

    def test_extension_only(self):
        self.assertEqual(self.av.classify(b'echo hi', 'run.bat')[0], 'script')
        self.assertEqual(self.av.classify(b'hello', 'notes.txt')[0], None)
        self.assertEqual(self.av.classify(b'', '')[0], None)

    def test_hash_parsing_skips_comments_and_noise(self):
        text = '# header\n%s\n"%s","2024-01-01","x"\nnot a hash\n%s\n' % ('a' * 64, 'B' * 64, 'c' * 63)
        got = self.av.parse_hashes(text)
        self.assertEqual(got, {bytes.fromhex('a' * 64), bytes.fromhex('b' * 64)})


class Service(AvCase):
    async def test_options(self):
        status, head, _ = await exchange(self.port, (
            'OPTIONS icap://127.0.0.1:1344/av ICAP/1.0\r\nHost: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n').encode())
        self.assertEqual(status, 200)
        self.assertIn('Methods: RESPMOD', head)

    async def test_eicar_is_blocked_and_recorded_without_the_query(self):
        status, head, rest = await exchange(self.port, respmod(EICAR, url='http://dl.example.com/eicar.com?token=SECRET'))
        self.assertEqual(status, 200)
        self.assertIn(b'403 Forbidden', rest)
        self.assertIn(b'EICAR', rest)
        ev = self.events()
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]['action'], ev[0]['file'], ev[0]['client']), ('blocked', 'eicar.com', '10.77.0.2'))
        self.assertNotIn('SECRET', json.dumps(ev))

    async def test_clean_file_passes(self):
        status, _, _ = await exchange(self.port, respmod(b'just some text'))
        self.assertEqual(status, 204)
        self.assertEqual(self.events(), [])

    async def test_custom_hash_and_monitor_mode(self):
        body = b'something bad ' * 20
        self.configure({'customHashes': [hashlib.sha256(body).hexdigest()], 'hashAction': 'monitor'})
        status, _, _ = await exchange(self.port, respmod(body))
        self.assertEqual(status, 204)
        self.assertEqual(self.events()[0]['action'], 'observed')

    async def test_file_type_block(self):
        self.configure({'types': {'executable': 'block'}})
        status, _, rest = await exchange(self.port, respmod(PE, url='http://dl.example.com/picture.jpg'))
        self.assertEqual(status, 200)
        self.assertIn(b'403', rest)
        self.assertEqual(self.events()[0]['kind'], 'executable')

    async def test_file_type_off_allows(self):
        self.configure({'types': {'archive': 'off'}})
        status, _, _ = await exchange(self.port, respmod(b'PK\x03\x04' + b'\x00' * 40, url='http://x.test/a.zip'))
        self.assertEqual(status, 204)

    async def test_gzip_transport_encoding_is_unpacked_for_the_hash(self):
        status, _, rest = await exchange(self.port, respmod(gzip.compress(EICAR), headers='Content-Encoding: gzip\r\n'))
        self.assertEqual(status, 200)
        self.assertIn(b'403', rest)

    async def test_error_responses_and_empty_bodies_are_ignored(self):
        status, _, _ = await exchange(self.port, respmod(EICAR, status='404 Not Found'))
        self.assertEqual(status, 204)
        status, _, _ = await exchange(self.port, respmod(EICAR, status='206 Partial Content'))
        self.assertEqual(status, 204)

    async def test_disabled_and_skipped_sites(self):
        self.configure({'enabled': False})
        status, _, _ = await exchange(self.port, respmod(EICAR))
        self.assertEqual(status, 204)
        self.configure({'skip': ['example.com']})
        status, _, _ = await exchange(self.port, respmod(EICAR))
        self.assertEqual(status, 204)

    async def test_oversize_files_are_not_hashed(self):
        self.configure({'maxSizeMb': 1})
        big = EICAR + b' ' * (2 * 1024 * 1024)
        status, _, _ = await exchange(self.port, respmod(big, chunks=[big[i:i + 65536] for i in range(0, len(big), 65536)]))
        self.assertEqual(status, 204)
        self.assertEqual(self.av.stats['skipped_large'], 1)


class Feed(AvCase):
    def test_check_and_status(self):
        with open(self.av.HASH_FILE, 'w') as f:
            f.write('# feed\n%s\n' % ('d' * 64))
        self.av.load_hashes(force=True)
        self.assertTrue(self.av.is_known('d' * 64))
        self.assertTrue(self.av.is_known(self.av.EICAR_SHA256))
        self.assertFalse(self.av.is_known('e' * 64))
        self.assertEqual(self.av.status()['hashes'], 2)

    def test_update_without_a_url_does_nothing(self):
        with open(os.environ['L7_INSPECTION_JSON'], 'w') as f:
            json.dump({'av': {'feed': {}}}, f)
        self.av.SETTINGS = os.environ['L7_INSPECTION_JSON']
        self.assertFalse(self.av.feed_update()['updated'])
        self.assertIn('skipped', self.av.feed_update(auto=True))

    def test_update_from_a_file_server_and_failed_update_keeps_the_old_list(self):
        import http.server
        import threading
        root = self.tmp.name
        with open(os.path.join(root, 'feed.txt'), 'w') as f:
            f.write('# bad hashes\n%s\n%s\n' % ('1' * 64, '2' * 64))

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **k):
                super().__init__(*a, directory=root, **k)

            def log_message(self, *a):
                pass
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Quiet)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            base = 'http://127.0.0.1:%d' % srv.server_address[1]
            with open(os.environ['L7_INSPECTION_JSON'], 'w') as f:
                json.dump({'av': {'feed': {'url': base + '/feed.txt', 'hours': 1}}}, f)
            self.av.SETTINGS = os.environ['L7_INSPECTION_JSON']
            self.assertEqual(self.av.feed_update(), {'updated': True, 'count': 2})
            self.av.load_hashes(force=True)
            self.assertTrue(self.av.is_known('1' * 64))
            self.assertIn('skipped', self.av.feed_update(auto=True))       # not due yet
            with open(os.environ['L7_INSPECTION_JSON'], 'w') as f:
                json.dump({'av': {'feed': {'url': base + '/missing.txt'}}}, f)
            res = self.av.feed_update()
            self.assertFalse(res['updated'])
            self.av.load_hashes(force=True)
            self.assertTrue(self.av.is_known('2' * 64))                     # old list kept
            self.assertTrue(self.av.feed_info()['error'])
        finally:
            srv.shutdown()


if __name__ == '__main__':
    unittest.main()
