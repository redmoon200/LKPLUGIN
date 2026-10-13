#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# ICAP server (RFC 3507) used by Squid for
#   /dlp  REQMOD   data-loss checks on what is sent to AI services
#   /av   RESPMOD  download protection: file types and hash reputation (avscan.py)
#
# Listens on 127.0.0.1 only. Settings come from inspection.json and are
# re-read on SIGHUP. Detections go to the audit chain in masked form; the
# request body itself is never written anywhere.

import asyncio
import json
import os
import re
import signal
import sys
import time
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit  # noqa: E402
import dlp_rules  # noqa: E402
import avscan  # noqa: E402

SETTINGS = os.environ.get('L7_INSPECTION_JSON', '/usr/local/etc/layer7security/inspection.json')
CATALOG = os.environ.get('L7_AI_CATALOG', '/usr/local/share/layer7security/ai_services.json')
ISTAG = '"l7icap-1"'
MAX_HEADER = 65536
IO_TIMEOUT = 30
BINARY_TYPES = ('image/', 'audio/', 'video/', 'font/', 'application/zip', 'application/pdf',
                'application/octet-stream', 'application/gzip', 'application/x-tar')

DEFAULTS = {
    'categories': {'card': 'block', 'id': 'block', 'api_key': 'block', 'code': 'monitor'},
    'codeMinLines': 12,
    'failMode': 'closed',
    'maxBodyKb': 4096,
    'blockMessage': ('This request was blocked by the organisation\'s data-loss prevention policy because it '
                     'appears to contain {what}. Remove the sensitive data and try again.'),
    'orgName': '',
}
CATEGORY_LABEL = {'card': 'a payment card number', 'id': 'a personal identity number',
                  'api_key': 'an API key or secret', 'code': 'source code'}

settings = dict(DEFAULTS)
services = {}
stats = {'requests': 0, 'detections': 0, 'blocked': 0, 'errors': 0, 'started': int(time.time())}
STATS_FILE = os.environ.get('L7_ICAP_STATS', '/var/run/layer7security/icap_stats.json')


def load_settings():
    global settings, services
    merged = dict(DEFAULTS)
    try:
        with open(SETTINGS) as f:
            data = json.load(f)
        merged['categories'] = dict(DEFAULTS['categories'], **{k: v for k, v in data.get('categories', {}).items()
                                                               if v in ('off', 'monitor', 'block')})
        for key in ('codeMinLines', 'maxBodyKb'):
            try:
                merged[key] = max(1, int(data.get(key, merged[key])))
            except (TypeError, ValueError):
                pass
        if data.get('failMode') in ('open', 'closed'):
            merged['failMode'] = data['failMode']
        if str(data.get('blockMessage', '')).strip():
            merged['blockMessage'] = str(data['blockMessage'])[:500]
        merged['orgName'] = str(data.get('orgName', ''))[:80]
        avscan.configure(data.get('av') or {})
    except (OSError, ValueError):
        pass
    settings = merged
    svc = {}
    try:
        with open(CATALOG) as f:
            for item in json.load(f):
                for dom in item.get('domains', []):
                    svc[dom.lower()] = item
    except (OSError, ValueError):
        pass
    services = svc


def service_for(host):
    host = (host or '').lower().split(':')[0]
    parts = host.split('.')
    for i in range(len(parts) - 1):
        hit = services.get('.'.join(parts[i:]))
        if hit:
            return hit
    return None


# ------------------------------------------------------------------- ICAP I/O


class IcapError(Exception):
    pass


async def read_headers(reader):
    data = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), IO_TIMEOUT)
    if len(data) > MAX_HEADER:
        raise IcapError('headers too large')
    return data


def parse_headers(block):
    lines = block.decode('latin-1').split('\r\n')
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    return lines[0], headers


async def read_chunked(reader, keep):
    """read a chunked body; keep at most `keep` bytes, drain the rest"""
    out = bytearray()
    total = 0
    truncated = False
    while True:
        line = await asyncio.wait_for(reader.readline(), IO_TIMEOUT)
        if not line:
            raise IcapError('connection closed in chunked body')
        size_txt = line.split(b';', 1)[0].strip()
        try:
            size = int(size_txt, 16)
        except ValueError:
            raise IcapError('bad chunk size')
        if size == 0:
            # optional trailer lines end with an empty line
            while True:
                tail = await asyncio.wait_for(reader.readline(), IO_TIMEOUT)
                if tail in (b'\r\n', b'\n', b''):
                    break
            break
        remaining = size
        while remaining:
            part = await asyncio.wait_for(reader.read(min(remaining, 65536)), IO_TIMEOUT)
            if not part:
                raise IcapError('connection closed in chunk')
            remaining -= len(part)
            total += len(part)
            if len(out) < keep:
                out += part[:keep - len(out)]
            else:
                truncated = True
        await asyncio.wait_for(reader.readexactly(2), IO_TIMEOUT)
    return bytes(out), total, truncated


def encapsulated(headers):
    """offsets from 'Encapsulated: req-hdr=0, req-body=412'"""
    items = []
    for part in headers.get('encapsulated', '').split(','):
        if '=' in part:
            name, off = part.strip().split('=', 1)
            if off.strip().isdigit():
                items.append((name.strip().lower(), int(off.strip())))
    return sorted(items, key=lambda x: x[1])


async def read_message(reader, headers, keep):
    """returns (dict of header blocks, body bytes, total body size, truncated)"""
    secs = encapsulated(headers)
    blocks = {}
    body, total, trunc = b'', 0, False
    for i, (name, off) in enumerate(secs):
        if name in ('null-body', 'req-body', 'res-body', 'opt-body'):
            if name != 'null-body':
                body, total, trunc = await read_chunked(reader, keep)
            continue
        nxt = secs[i + 1][1] if i + 1 < len(secs) else off
        blocks[name] = await asyncio.wait_for(reader.readexactly(max(0, nxt - off)), IO_TIMEOUT)
    return blocks, body, total, trunc


def icap_response(code, text, extra=None, encaps='null-body=0', payload=b''):
    head = 'ICAP/1.0 %d %s\r\nISTag: %s\r\nConnection: keep-alive\r\n' % (code, text, ISTAG)
    for k, v in (extra or {}).items():
        head += '%s: %s\r\n' % (k, v)
    head += 'Encapsulated: %s\r\n\r\n' % encaps
    return head.encode('latin-1') + payload


def chunk(data):
    return ('%x\r\n' % len(data)).encode() + data + b'\r\n' + b'0\r\n\r\n' if data else b'0\r\n\r\n'


def options_response(method):
    return icap_response(200, 'OK', {'Methods': method, 'Service': 'os-layer7security',
                                     'Allow': '204', 'Options-TTL': '3600', 'Max-Connections': '200',
                                     'Transfer-Complete': '*'})


def block_response(request_headers, message, tag):
    ctype = request_headers.get('content-type', '').lower()
    wants_json = 'json' in ctype or 'json' in request_headers.get('accept', '').lower()
    if wants_json:
        body = json.dumps({'error': {'message': message, 'type': 'dlp_blocked', 'code': 'data_loss_prevention'}}).encode()
        ctype_out = 'application/json'
    else:
        safe = message.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        body = ('<!doctype html><title>Blocked</title><meta charset="utf-8"><body style="font-family:sans-serif;'
                'max-width:40em;margin:3em auto"><h1>Request blocked</h1><p>%s</p></body>' % safe).encode()
        ctype_out = 'text/html; charset=utf-8'
    http = ('HTTP/1.1 403 Forbidden\r\nContent-Type: %s\r\nContent-Length: %d\r\nCache-Control: no-store\r\n'
            'X-L7-DLP: %s\r\nConnection: close\r\n\r\n' % (ctype_out, len(body), tag)).encode()
    return icap_response(200, 'OK', encaps='res-hdr=0, res-body=%d' % len(http), payload=http + chunk(body))


# ----------------------------------------------------------------- DLP logic


def multipart_text(body, boundary):
    """text parts of a multipart body; file parts with binary types are skipped"""
    out = []
    sep = b'--' + boundary.encode('latin-1')
    for part in body.split(sep)[1:]:
        head, _, content = part.partition(b'\r\n\r\n')
        low = head.lower()
        if b'content-type:' in low and any(t.encode() in low for t in BINARY_TYPES):
            continue
        out.append(content.rsplit(b'\r\n', 1)[0].decode('utf-8', 'replace'))
    return '\n'.join(out)


def body_text(headers, body):
    ctype = headers.get('content-type', '').lower()
    if ctype.startswith(BINARY_TYPES) and 'json' not in ctype:
        return ''
    if ctype.startswith('multipart/'):
        m = re.search(r'boundary="?([^";]+)"?', headers.get('content-type', ''), re.I)
        if m:
            return multipart_text(dlp_rules.decode_body(body, headers.get('content-encoding', '')), m.group(1))
    return dlp_rules.extract_text(body, ctype, headers.get('content-encoding', ''))


def analyse(text):
    """list of (category, rule, masked snippet / summary) honouring the configured actions"""
    cats = [c for c, a in settings['categories'].items() if a != 'off']
    found = {}
    for det in dlp_rules.scan(text, cats, settings['codeMinLines']):
        found.setdefault(det.category, []).append(det)
    return found


def record_detection(cfg, client, host, category, dets, text, action):
    svc = service_for(host)
    first = dets[0]
    if category == 'code':
        parts = first.rule.split(':')
        detail = 'source code: about %s lines, language %s' % (parts[2] if len(parts) > 2 else '?', parts[1] if len(parts) > 1 else '?')
    else:
        rules = sorted({d.rule for d in dets})
        detail = '%d x %s: %s' % (len(dets), '/'.join(rules), dlp_rules.snippet(text, first))
    audit.append('dlp-block' if action == 'blocked' else 'dlp-detect', action, client=client,
                 user=audit.user_for(cfg, client), service=svc['name'] if svc else '', host=host,
                 category=category, detail=detail, count=len(dets), source='icap', cfg=cfg)


async def handle_dlp(method, uri, headers, blocks, body, total, truncated):
    if method == 'OPTIONS':
        return options_response('REQMOD')
    if method != 'REQMOD':
        return icap_response(405, 'Method not allowed')
    req_hdr = blocks.get('req-hdr', b'')
    line, rheaders = parse_headers(req_hdr.rstrip(b'\r\n') + b'\r\n\r\n')
    parts = line.split(' ')
    host = urlsplit(parts[1]).hostname if len(parts) > 1 and '://' in parts[1] else ''
    host = host or rheaders.get('host', '')
    client = headers.get('x-client-ip', '')
    stats['requests'] += 1
    if not body:
        return icap_response(204, 'No Content')
    text = body_text(rheaders, body)
    if not text.strip():
        return icap_response(204, 'No Content')
    found = analyse(text)
    if not found:
        return icap_response(204, 'No Content')
    cfg = audit.config()
    blocked = []
    for category, dets in found.items():
        action = settings['categories'].get(category, 'off')
        stats['detections'] += len(dets)
        record_detection(cfg, client, host, category, dets, text, 'blocked' if action == 'block' else 'observed')
        if action == 'block':
            blocked.append(category)
    if blocked:
        stats['blocked'] += 1
        what = ' and '.join(CATEGORY_LABEL[c] for c in blocked)
        msg = settings['blockMessage'].replace('{what}', what)
        if settings['orgName']:
            msg = '[%s] %s' % (settings['orgName'], msg)
        return block_response(rheaders, msg, ','.join(blocked))
    return icap_response(204, 'No Content')


HANDLERS = {'/dlp': handle_dlp}
KEEP = {}


def register(path, handler, keep=None):
    """keep: callable giving how many body bytes the service needs buffered"""
    HANDLERS[path] = handler
    if keep:
        KEEP[path] = keep


avscan.bind(sys.modules[__name__])
register('/av', avscan.handle_av, avscan.keep_bytes)


async def serve_client(reader, writer):
    try:
        while True:
            try:
                head = await read_headers(reader)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                break
            line, headers = parse_headers(head)
            bits = line.split(' ')
            if len(bits) < 3 or not bits[2].startswith('ICAP/'):
                writer.write(icap_response(400, 'Bad request'))
                break
            method, uri = bits[0].upper(), bits[1]
            path = urlsplit(uri).path.rstrip('/') or '/'
            handler = HANDLERS.get(path)
            keep = KEEP[path]() if path in KEEP else settings['maxBodyKb'] * 1024
            try:
                blocks, body, total, trunc = await read_message(reader, headers, keep if method != 'OPTIONS' else 0)
                if handler is None:
                    writer.write(icap_response(404, 'Service not found'))
                else:
                    writer.write(await handler(method, uri, headers, blocks, body, total, trunc))
            except (IcapError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                stats['errors'] += 1
                break
            except Exception as exc:  # a scanning bug must not take the proxy down
                stats['errors'] += 1
                sys.stderr.write('handler error: %r\n' % (exc,))
                if settings['failMode'] == 'open':
                    writer.write(icap_response(204, 'No Content'))
                else:
                    writer.write(icap_response(500, 'Internal error'))
            await writer.drain()
    finally:
        try:
            writer.close()
        except OSError:
            pass


def write_stats():
    try:
        os.makedirs(os.path.dirname(STATS_FILE), exist_ok=True)
        with open(STATS_FILE + '.tmp', 'w') as f:
            json.dump(dict(stats, ts=int(time.time())), f)
        os.replace(STATS_FILE + '.tmp', STATS_FILE)
    except OSError:
        pass


async def stats_loop():
    while True:
        write_stats()
        await asyncio.sleep(5)


async def main(host='127.0.0.1', port=1344):
    load_settings()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGHUP, load_settings)
    server = await asyncio.start_server(serve_client, host, port, limit=2 ** 20)
    asyncio.ensure_future(stats_loop())
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 1344
    try:
        asyncio.run(main(port=port))
    except KeyboardInterrupt:
        pass
