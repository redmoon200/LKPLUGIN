#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Tests of the ICAP server: speaks to it like Squid does, over a real socket.
#   python3 -m unittest tests/test_icap.py

import asyncio
import gzip
import importlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'security', 'layer7security', 'src',
                       'opnsense', 'scripts', 'OPNsense', 'Layer7Security')
sys.path.insert(0, SCRIPTS)

CONFIG = '''<opnsense><OPNsense><layer7security>
<audit><enabled>1</enabled><retentionDays>30</retentionDays><syslogLocal>0</syslogLocal></audit>
<users><user><name>alice</name><addresses>10.77.0.2</addresses></user></users>
</layer7security></OPNsense></opnsense>'''

CARD = '4111 1111 1111 1111'
KEY = 'sk-ant-' + 'api03-' + 'aB3dE5gH7jK9mN1pQ3sT5v'
CODE = '\n'.join(['import os', 'import sys', 'def main(argv):', '    total = 0', '    for n in argv:',
                  '        if os.path.exists(n):', '            total += os.path.getsize(n)', '    print(total)',
                  '    return 0', 'class Reader:', '    def __init__(self, p):', '        self.p = p',
                  '    def run(self):', '        return self.p'])


def reqmod(body, ctype='application/json', host='claude.ai', client='10.77.0.2', encoding=None, chunks=None,
           method='REQMOD', path='/dlp'):
    extra = 'Content-Encoding: %s\r\n' % encoding if encoding else ''
    http = ('POST https://%s/api/chat HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\n%sContent-Length: %d\r\n\r\n'
            % (host, host, ctype, extra, len(body))).encode()
    icap = ('%s icap://127.0.0.1:1344%s ICAP/1.0\r\nHost: 127.0.0.1\r\nAllow: 204\r\nX-Client-IP: %s\r\n'
            'Encapsulated: req-hdr=0, req-body=%d\r\n\r\n' % (method, path, client, len(http))).encode()
    out = icap + http
    pieces = chunks or [body]
    for piece in pieces:
        out += ('%x\r\n' % len(piece)).encode() + piece + b'\r\n'
    return out + b'0\r\n\r\n'


async def exchange(port, payload, expect_close=False):
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


class IcapCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        t = self.tmp.name
        self.audit_db = os.path.join(t, 'audit.db')
        os.environ.update({'L7_AUDIT_DB': self.audit_db, 'L7_CONFIG': os.path.join(t, 'config.xml'),
                           'L7_INSPECTION_JSON': os.path.join(t, 'inspection.json'),
                           'L7_AI_CATALOG': os.path.join(t, 'ai.json'), 'L7_ICAP_STATS': os.path.join(t, 'stats.json')})
        open(os.environ['L7_CONFIG'], 'w').write(CONFIG)
        json.dump([{'id': 'claude', 'name': 'Claude / Anthropic', 'domains': ['claude.ai', 'anthropic.com']}],
                  open(os.environ['L7_AI_CATALOG'], 'w'))
        self.set_inspection({})
        import audit
        import icap_server
        importlib.reload(audit)
        self.icap = importlib.reload(icap_server)
        self.icap.load_settings()
        self.server = await asyncio.start_server(self.icap.serve_client, '127.0.0.1', 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self.tmp.cleanup()

    def set_inspection(self, data):
        json.dump(data, open(os.environ['L7_INSPECTION_JSON'], 'w'))

    def records(self):
        if not os.path.exists(self.audit_db):
            return []
        con = sqlite3.connect(self.audit_db)
        con.row_factory = sqlite3.Row
        rows = [dict(r) for r in con.execute('SELECT * FROM audit ORDER BY seq')]
        con.close()
        return rows

    def chat(self, text):
        return json.dumps({'messages': [{'role': 'user', 'content': text}]}).encode()


class Protocol(IcapCase):
    async def test_options(self):
        status, head, _ = await exchange(self.port, (
            'OPTIONS icap://127.0.0.1:1344/dlp ICAP/1.0\r\nHost: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n').encode())
        self.assertEqual(status, 200)
        self.assertIn('Methods: REQMOD', head)
        self.assertIn('Allow: 204', head)

    async def test_unknown_service_and_garbage(self):
        status, _, _ = await exchange(self.port, reqmod(b'x', path='/nope'))
        self.assertEqual(status, 404)
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        writer.write(b'GET / HTTP/1.1\r\n\r\n')
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
        self.assertIn(b'400', head)
        writer.close()
        status, _, _ = await exchange(self.port, reqmod(b'{}'))      # still serving afterwards
        self.assertEqual(status, 204)

    async def test_truncated_body_does_not_hang_or_crash(self):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        writer.write(reqmod(self.chat('hello'))[:-12])
        await writer.drain()
        writer.close()
        status, _, _ = await exchange(self.port, reqmod(b'{}'))
        self.assertEqual(status, 204)

    async def test_persistent_connection_serves_several_requests(self):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        for _ in range(3):
            writer.write(reqmod(self.chat('hello there')))
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
            self.assertIn(b'204', head)
        writer.close()


class Detection(IcapCase):
    async def test_clean_request_passes_without_a_record(self):
        status, _, _ = await exchange(self.port, reqmod(self.chat('Explain how photosynthesis works.')))
        self.assertEqual(status, 204)
        self.assertEqual(self.records(), [])

    async def test_card_in_json_is_blocked_with_a_json_error(self):
        status, head, rest = await exchange(self.port, reqmod(self.chat('My card is %s please remember it' % CARD)))
        self.assertEqual(status, 200)
        self.assertIn(b'403 Forbidden', rest)
        self.assertIn(b'payment card number', rest)
        self.assertNotIn(b'4111', rest)
        recs = self.records()
        self.assertEqual(len(recs), 1)
        self.assertEqual((recs[0]['kind'], recs[0]['action'], recs[0]['category']), ('dlp-block', 'blocked', 'card'))
        self.assertEqual((recs[0]['user'], recs[0]['service'], recs[0]['client']), ('alice', 'Claude / Anthropic', '10.77.0.2'))
        self.assertNotIn('4111 1111 1111', recs[0]['detail'])

    async def test_monitor_mode_logs_but_passes(self):
        self.set_inspection({'categories': {'card': 'monitor'}})
        self.icap.load_settings()
        status, _, _ = await exchange(self.port, reqmod(self.chat('card %s' % CARD)))
        self.assertEqual(status, 204)
        self.assertEqual([(r['kind'], r['action']) for r in self.records()], [('dlp-detect', 'observed')])

    async def test_off_category_is_ignored(self):
        self.set_inspection({'categories': {'card': 'off'}})
        self.icap.load_settings()
        status, _, _ = await exchange(self.port, reqmod(self.chat('card %s' % CARD)))
        self.assertEqual(status, 204)
        self.assertEqual(self.records(), [])

    async def test_api_key_blocked_and_masked_in_the_log(self):
        status, _, rest = await exchange(self.port, reqmod(self.chat('here is my key ' + KEY)))
        self.assertEqual(status, 200)
        rec = self.records()[0]
        self.assertEqual(rec['category'], 'api_key')
        self.assertNotIn('aB3dE5gH7', rec['detail'])
        self.assertIn('anthropic', rec['detail'])

    async def test_source_code_is_monitored_without_storing_code(self):
        status, _, _ = await exchange(self.port, reqmod(self.chat(CODE)))
        self.assertEqual(status, 204)                      # default action for code is monitor
        rec = self.records()[0]
        self.assertEqual(rec['category'], 'code')
        self.assertIn('python', rec['detail'])
        self.assertNotIn('os.path', rec['detail'])

    async def test_code_can_be_blocked(self):
        self.set_inspection({'categories': {'code': 'block'}})
        self.icap.load_settings()
        status, _, rest = await exchange(self.port, reqmod(self.chat(CODE)))
        self.assertEqual(status, 200)
        self.assertIn(b'source code', rest)

    async def test_gzip_and_chunked_and_escaped_bodies(self):
        body = self.chat('card %s' % CARD)
        status, _, _ = await exchange(self.port, reqmod(gzip.compress(body), encoding='gzip'))
        self.assertEqual(status, 200)
        pieces = [body[i:i + 7] for i in range(0, len(body), 7)]
        status, _, _ = await exchange(self.port, reqmod(body, chunks=pieces))
        self.assertEqual(status, 200)
        escaped = ('{"p": "card ' + ''.join('\\u%04x' % ord(c) for c in CARD) + '"}').encode()
        status, _, _ = await exchange(self.port, reqmod(escaped))
        self.assertEqual(status, 200)

    async def test_binary_uploads_are_not_scanned(self):
        status, _, _ = await exchange(self.port, reqmod(CARD.encode() * 50, ctype='application/octet-stream'))
        self.assertEqual(status, 204)
        status, _, _ = await exchange(self.port, reqmod(CARD.encode(), ctype='image/png'))
        self.assertEqual(status, 204)

    async def test_multipart_text_part_scanned_file_part_skipped(self):
        b = 'XBOUNDARY'
        parts = ('--%s\r\nContent-Disposition: form-data; name="file"; filename="a.bin"\r\nContent-Type: application/zip\r\n\r\n%s\r\n'
                 '--%s\r\nContent-Disposition: form-data; name="prompt"\r\n\r\nnothing special\r\n--%s--\r\n' % (b, CARD, b, b)).encode()
        status, _, _ = await exchange(self.port, reqmod(parts, ctype='multipart/form-data; boundary=' + b))
        self.assertEqual(status, 204)
        parts2 = parts.replace(b'nothing special', CARD.encode())
        status, _, _ = await exchange(self.port, reqmod(parts2, ctype='multipart/form-data; boundary=' + b))
        self.assertEqual(status, 200)

    async def test_html_error_for_non_json_clients(self):
        status, _, rest = await exchange(self.port, reqmod(('card=%s' % CARD).encode(), ctype='application/x-www-form-urlencoded'))
        self.assertEqual(status, 200)
        self.assertIn(b'text/html', rest)

    async def test_custom_message_and_org_name(self):
        self.set_inspection({'blockMessage': 'Policy 7: {what} is not allowed.', 'orgName': 'Example Corp'})
        self.icap.load_settings()
        _, _, rest = await exchange(self.port, reqmod(self.chat('card %s' % CARD)))
        self.assertIn(b'[Example Corp] Policy 7: a payment card number is not allowed.', rest)

    async def test_deeply_nested_json_is_survivable(self):
        status, _, _ = await exchange(self.port, reqmod(b'[' * 20000))
        self.assertEqual(status, 204)

    async def test_body_limit_scans_the_prefix_only(self):
        self.set_inspection({'maxBodyKb': 1})
        self.icap.load_settings()
        text = 'a' * 4000 + ' card ' + CARD
        status, _, _ = await exchange(self.port, reqmod(text.encode(), ctype='text/plain'))
        self.assertEqual(status, 204)                      # beyond the limit: not scanned

    async def test_fail_modes(self):
        original = self.icap.analyse

        def boom(_):
            raise RuntimeError('detector bug')
        self.icap.analyse = boom
        try:
            status, _, _ = await exchange(self.port, reqmod(self.chat('hello world')))
            self.assertEqual(status, 500)                  # closed by default
            self.set_inspection({'failMode': 'open'})
            self.icap.load_settings()
            status, _, _ = await exchange(self.port, reqmod(self.chat('hello world')))
            self.assertEqual(status, 204)
        finally:
            self.icap.analyse = original

    async def test_audit_chain_stays_valid(self):
        for text in ('card %s' % CARD, 'key ' + KEY, 'card %s' % CARD):
            await exchange(self.port, reqmod(self.chat(text)))
        import audit
        self.assertTrue(importlib.reload(audit).verify()['ok'])
        self.assertEqual(len(self.records()), 3)


if __name__ == '__main__':
    unittest.main()
