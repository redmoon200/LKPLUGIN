#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Web download protection without a signature engine:
#   * file-type control: executables, scripts, installer packages and archives are
#     recognised by their first bytes and file name (not by what the server claims)
#   * hash reputation: the SHA-256 of every download is looked up in a feed of known
#     malware hashes, a list you maintain, and the EICAR test file
# Used as the /av RESPMOD service of icap_server.py, and from the command line:
#
#   avscan.py status
#   avscan.py list ROWS OFFSET PERIOD PHRASE
#   avscan.py feed-update [auto]
#   avscan.py check SHA256
#   avscan.py prune
#
# Only the file name (no query string), size, type and hash of a detection are kept.

import asyncio
import hashlib
import io
import json
import os
import re
import sqlite3
import sys
import time
import urllib.request
import zipfile
import zlib
from urllib.parse import urlsplit

SETTINGS = os.environ.get('L7_INSPECTION_JSON', '/usr/local/etc/layer7security/inspection.json')
AV_DB = os.environ.get('L7_AV_DB', '/var/db/layer7security/av.db')
HASH_FILE = os.environ.get('L7_AV_HASHES', '/var/db/layer7security/av_hashes.txt')
FEED_INFO = os.environ.get('L7_AV_FEED_INFO', '/var/db/layer7security/av_feed.json')
RETENTION_DAYS = 90
MAX_FEED = 128 * 1024 * 1024
EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
HEX64 = re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])')
PERIODS = (300, 3600, 21600, 86400, 604800, 2592000, 31536000)

TYPE_LABEL = {'executable': 'a program', 'script': 'a script', 'package': 'an installer package',
              'archive': 'an archive'}
EXT = {
    'executable': {'exe', 'dll', 'scr', 'com', 'sys', 'cpl', 'ocx', 'elf', 'so', 'dylib'},
    'script': {'ps1', 'psm1', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'sh', 'py', 'pl', 'rb', 'lnk'},
    'package': {'msi', 'msix', 'appx', 'apk', 'jar', 'deb', 'rpm', 'dmg', 'pkg', 'appimage', 'iso', 'img', 'cab', 'vhd', 'vhdx'},
    'archive': {'zip', 'rar', '7z', 'gz', 'tgz', 'tar', 'bz2', 'xz', 'zst', 'z', 'lz'},
}
OFFICE_ZIP = {'docx', 'docm', 'xlsx', 'xlsm', 'pptx', 'pptm', 'odt', 'ods', 'odp', 'epub', 'xpi', 'whl', 'nupkg'}

settings = {'enabled': False, 'types': {}, 'hashAction': 'block', 'maxSizeMb': 50, 'skip': [],
            'customHashes': [], 'failMode': 'open'}
hashes = set()
hash_state = {'mtime': None, 'custom': None, 'checked': 0}
stats = {'scanned': 0, 'detections': 0, 'blocked': 0, 'skipped_large': 0}
ICAP = None


def bind(mod):
    """the icap_server module (its response helpers); avoids a circular import"""
    global ICAP
    ICAP = mod


def configure(av):
    global settings
    types = {k: v for k, v in (av.get('types') or {}).items() if k in TYPE_LABEL and v in ('off', 'monitor', 'block')}
    custom = [h.lower() for h in av.get('customHashes', []) if isinstance(h, str) and re.fullmatch(r'[0-9a-fA-F]{64}', h)]
    try:
        size = max(1, int(av.get('maxSizeMb', 50)))
    except (TypeError, ValueError):
        size = 50
    settings = {
        'enabled': bool(av.get('enabled')), 'types': types,
        'hashAction': av.get('hashAction') if av.get('hashAction') in ('off', 'monitor', 'block') else 'block',
        'maxSizeMb': size, 'skip': [d.lower().lstrip('.') for d in av.get('skip', []) if isinstance(d, str)],
        'customHashes': custom, 'failMode': av.get('failMode', 'open'), 'feed': av.get('feed') or {},
    }
    hash_state['custom'] = None


def keep_bytes():
    return settings['maxSizeMb'] * 1024 * 1024


# ----------------------------------------------------------------- file types


def extension(name):
    name = (name or '').lower().rsplit('/', 1)[-1]
    return name.rsplit('.', 1)[-1] if '.' in name else ''


def classify(head, name=''):
    """(category, label) from the first bytes and file name, or (None, '')"""
    ext = extension(name)
    h = head[:512]
    if h[:2] == b'MZ':
        return 'executable', 'Windows program (PE)'
    if h[:4] == b'\x7fELF':
        return 'executable', 'Linux program (ELF)'
    if h[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
        return 'executable', 'macOS program (Mach-O)'
    if h[:4] == b'\xca\xfe\xba\xbe':
        if int.from_bytes(h[4:8], 'big') <= 20:
            return 'executable', 'macOS universal program'
        return 'package', 'Java class file'
    if h[:2] == b'#!':
        return 'script', 'shebang line'
    if h[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' and ext == 'msi':
        return 'package', 'Windows Installer'
    if h[:4] == b'PK\x03\x04':
        if ext in OFFICE_ZIP:
            return None, ''
        if ext in EXT['package']:
            return 'package', ext + ' package'
        return 'archive', 'zip archive'
    if h[:4] == b'Rar!':
        return 'archive', 'rar archive'
    if h[:6] == b'7z\xbc\xaf\x27\x1c':
        return 'archive', '7z archive'
    if h[:3] == b'\x1f\x8b\x08':
        return 'archive', 'gzip archive'
    if h[:3] == b'BZh':
        return 'archive', 'bzip2 archive'
    if h[:6] == b'\xfd7zXZ\x00':
        return 'archive', 'xz archive'
    if h[:4] == b'\x28\xb5\x2f\xfd':
        return 'archive', 'zstd archive'
    if h[:4] == b'!<ar' and ext == 'deb':
        return 'package', 'Debian package'
    if h[:4] == b'\xed\xab\xee\xdb':
        return 'package', 'RPM package'
    if len(head) > 262 and head[257:262] == b'ustar':
        return 'archive', 'tar archive'
    for cat in ('executable', 'script', 'package', 'archive'):
        if ext in EXT[cat]:
            return cat, ext + ' file'
    return None, ''


# -------------------------------------------------------------- hash reputation


def parse_hashes(text):
    out = set()
    for line in text.splitlines():
        if line.startswith('#'):
            continue
        m = HEX64.search(line)
        if m:
            out.add(bytes.fromhex(m.group(0)))
    return out


def load_hashes(force=False):
    """feed file + custom list + EICAR, reloaded when the feed file changes"""
    now = time.time()
    if not force and now - hash_state['checked'] < 20 and hash_state['custom'] is not None:
        return
    hash_state['checked'] = now
    try:
        mtime = os.stat(HASH_FILE).st_mtime
    except OSError:
        mtime = None
    custom = tuple(settings['customHashes'])
    if not force and mtime == hash_state['mtime'] and custom == hash_state['custom']:
        return
    new = set()
    if mtime is not None:
        try:
            with open(HASH_FILE, errors='replace') as f:
                new |= parse_hashes(f.read())
        except OSError:
            pass
    new |= {bytes.fromhex(h) for h in custom}
    new.add(bytes.fromhex(EICAR_SHA256))
    hashes.clear()
    hashes.update(new)
    hash_state['mtime'], hash_state['custom'] = mtime, custom


def is_known(digest_hex):
    load_hashes()
    return bytes.fromhex(digest_hex) in hashes


def feed_info():
    try:
        with open(FEED_INFO) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def feed_update(auto=False):
    """download the hash feed; keeps the old list when the download fails or is empty"""
    try:
        with open(SETTINGS) as f:
            feed = (json.load(f).get('av') or {}).get('feed') or {}
    except (OSError, ValueError):
        feed = {}
    url = str(feed.get('url', '')).strip()
    info = feed_info()
    if not url:
        if auto:
            return {'updated': False, 'skipped': 'no feed configured'}
        return {'updated': False, 'error': 'no feed URL configured'}
    if not re.match(r'^https?://', url):
        return {'updated': False, 'error': 'the feed URL must start with http:// or https://'}
    if auto and info.get('ts') and time.time() - info['ts'] < max(1, int(feed.get('hours') or 24)) * 3600 - 300:
        return {'updated': False, 'skipped': 'not due yet'}
    req = urllib.request.Request(url, headers={'User-Agent': 'os-layer7security'})
    if feed.get('authKey'):
        req.add_header('Auth-Key', str(feed['authKey']))
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read(MAX_FEED + 1)
        if len(data) > MAX_FEED:
            raise ValueError('the feed is larger than %d MB' % (MAX_FEED // 1048576))
        if data[:4] == b'PK\x03\x04':
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = [n for n in z.namelist() if not n.endswith('/')]
                if not names:
                    raise ValueError('the zip file is empty')
                data = z.read(names[0])
        found = parse_hashes(data.decode('utf-8', 'replace'))
        if not found:
            raise ValueError('no SHA-256 hashes found in the download')
    except Exception as exc:
        info.update(error=str(exc)[:200], last_try=int(time.time()))
        write_feed_info(info)
        return {'updated': False, 'error': info['error']}
    os.makedirs(os.path.dirname(HASH_FILE), exist_ok=True)
    with open(HASH_FILE + '.tmp', 'w') as f:
        f.write('# downloaded from the configured feed\n')
        f.write('\n'.join(h.hex() for h in sorted(found)) + '\n')
    os.replace(HASH_FILE + '.tmp', HASH_FILE)
    info = {'ts': int(time.time()), 'count': len(found), 'url': re.sub(r'\?.*$', '', url), 'error': ''}
    write_feed_info(info)
    return {'updated': True, 'count': len(found)}


def write_feed_info(info):
    try:
        os.makedirs(os.path.dirname(FEED_INFO), exist_ok=True)
        with open(FEED_INFO + '.tmp', 'w') as f:
            json.dump(info, f)
        os.replace(FEED_INFO + '.tmp', FEED_INFO)
    except OSError:
        pass


# ------------------------------------------------------------------ detections

SCHEMA = """CREATE TABLE IF NOT EXISTS av_events(
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, client TEXT, host TEXT, file TEXT, size INTEGER,
  kind TEXT, label TEXT, sha256 TEXT, action TEXT, reason TEXT);
CREATE INDEX IF NOT EXISTS av_ts ON av_events(ts);"""


def connect():
    os.makedirs(os.path.dirname(AV_DB), exist_ok=True)
    con = sqlite3.connect(AV_DB, timeout=10)
    con.executescript(SCHEMA)
    try:
        os.chmod(AV_DB, 0o600)
    except OSError:
        pass
    return con


def clean(text, limit=120):
    return re.sub(r'[\x00-\x1f\x7f]', '', str(text or ''))[:limit]


def record(client, host, name, size, kind, label, digest, action, reason):
    try:
        con = connect()
        with con:
            con.execute('INSERT INTO av_events(ts,client,host,file,size,kind,label,sha256,action,reason) '
                        'VALUES(?,?,?,?,?,?,?,?,?,?)',
                        (int(time.time()), clean(client, 64), clean(host, 120), clean(name), int(size), kind, clean(label, 60),
                         digest, action, clean(reason, 160)))
        con.close()
    except sqlite3.Error as exc:
        sys.stderr.write('av record failed: %r\n' % (exc,))


def prune():
    con = connect()
    with con:
        n = con.execute('DELETE FROM av_events WHERE ts < ?', (int(time.time()) - RETENTION_DAYS * 86400,)).rowcount
    con.close()
    return {'removed': n}


def listing(rows, offset, per, phrase):
    con = connect()
    args = [int(time.time()) - per]
    where = 'ts >= ?'
    if phrase:
        where += ' AND (client LIKE ? OR host LIKE ? OR file LIKE ? OR reason LIKE ? OR sha256 LIKE ?)'
        args += ['%' + phrase + '%'] * 5
    total = con.execute('SELECT COUNT(*) FROM av_events WHERE ' + where, args).fetchone()[0]
    cur = con.execute('SELECT id,ts,client,host,file,size,kind,label,sha256,action,reason FROM av_events WHERE ' + where +
                      ' ORDER BY id DESC LIMIT ? OFFSET ?', args + [rows, offset])
    cols = [c[0] for c in cur.description]
    out = [dict(zip(cols, r)) for r in cur.fetchall()]
    con.close()
    return {'total': total, 'rowCount': len(out), 'rows': out}


def status():
    load_hashes(force=True)
    info = feed_info()
    con = connect()
    day = int(time.time()) - 86400
    det = con.execute('SELECT COUNT(*), COALESCE(SUM(action="blocked"),0) FROM av_events WHERE ts >= ?', (day,)).fetchone()
    con.close()
    return {'hashes': len(hashes), 'feedTs': info.get('ts', 0), 'feedCount': info.get('count', 0),
            'feedError': info.get('error', ''), 'feedUrl': info.get('url', ''), 'detections24h': det[0], 'blocked24h': det[1]}


# ------------------------------------------------------------------ ICAP service


def unpack(data, headers):
    """the file as the user gets it: transport compression removed (bounded)"""
    enc = headers.get('content-encoding', '').lower()
    if enc in ('gzip', 'x-gzip', 'deflate'):
        try:
            d = zlib.decompressobj(31 if 'gzip' in enc else 15)
            return d.decompress(data, keep_bytes())
        except zlib.error:
            return data
    return data


def filename_for(url, headers):
    m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', headers.get('content-disposition', ''), re.I)
    if m:
        return m.group(1).strip()
    return os.path.basename(urlsplit(url).path)


def block_page(reason):
    safe = reason.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    body = ('<!doctype html><title>Download blocked</title><meta charset="utf-8"><body style="font-family:sans-serif;'
            'max-width:40em;margin:3em auto"><h1>Download blocked</h1><p>%s</p></body>' % safe).encode()
    http = ('HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\n'
            'Cache-Control: no-store\r\nX-L7-AV: blocked\r\nConnection: close\r\n\r\n' % len(body)).encode()
    return ICAP.icap_response(200, 'OK', encaps='res-hdr=0, res-body=%d' % len(http), payload=http + ICAP.chunk(body))


def scan(head_data, full_data, name, truncated):
    """-> (action, kind, label, digest, reason) where action is 'blocked', 'observed' or None"""
    kind, label = classify(head_data, name)
    digest = ''
    if not truncated and settings['hashAction'] != 'off':
        digest = hashlib.sha256(full_data).hexdigest()
        if is_known(digest):
            act = 'blocked' if settings['hashAction'] == 'block' else 'observed'
            why = 'matches a known malware hash' if digest != EICAR_SHA256 else 'is the EICAR test file'
            return act, kind or 'hash', label or 'known hash', digest, 'the file ' + why
    if kind:
        mode = settings['types'].get(kind, 'monitor')
        if mode == 'block':
            return 'blocked', kind, label, digest, 'the file is ' + TYPE_LABEL[kind] + ' (' + label + ')'
        if mode == 'monitor':
            return 'observed', kind, label, digest, 'the file is ' + TYPE_LABEL[kind] + ' (' + label + ')'
    return None, kind or '', label, digest, ''


async def handle_av(method, uri, headers, blocks, body, total, truncated):
    if method == 'OPTIONS':
        return ICAP.options_response('RESPMOD')
    if method != 'RESPMOD':
        return ICAP.icap_response(405, 'Method not allowed')
    if not settings['enabled']:
        return ICAP.icap_response(204, 'No Content')
    res_line, rh = ICAP.parse_headers(blocks.get('res-hdr', b'').rstrip(b'\r\n') + b'\r\n\r\n')
    code = res_line.split(' ')[1] if len(res_line.split(' ')) > 1 else ''
    if code != '200' or not body:
        return ICAP.icap_response(204, 'No Content')
    req_line, qh = ICAP.parse_headers(blocks.get('req-hdr', b'').rstrip(b'\r\n') + b'\r\n\r\n')
    parts = req_line.split(' ')
    url = parts[1] if len(parts) > 1 else ''
    host = (urlsplit(url).hostname if '://' in url else '') or qh.get('host', '').split(':')[0]
    host = (host or '').lower()
    if any(host == d or host.endswith('.' + d) for d in settings['skip']):
        return ICAP.icap_response(204, 'No Content')
    ICAP.stats['requests'] += 1
    stats['scanned'] += 1
    name = filename_for(url, rh)
    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(None, unpack, body, rh)
    if truncated:
        stats['skipped_large'] += 1
    act, kind, label, digest, reason = await loop.run_in_executor(None, scan, data[:600], data, name, truncated)
    if not act:
        return ICAP.icap_response(204, 'No Content')
    client = headers.get('x-client-ip', '')
    stats['detections'] += 1
    record(client, host, name, total, kind, label, digest, act, reason)
    if act == 'blocked':
        stats['blocked'] += 1
        return block_page('This download was blocked because ' + reason + '.')
    return ICAP.icap_response(204, 'No Content')


# --------------------------------------------------------------------- CLI


def load_cli_settings():
    try:
        with open(SETTINGS) as f:
            configure((json.load(f).get('av')) or {})
    except (OSError, ValueError):
        pass


def main(argv):
    cmd = argv[1] if len(argv) > 1 else 'status'
    load_cli_settings()
    if cmd == 'status':
        out = status()
    elif cmd == 'list':
        rows = max(1, min(500, int(argv[2]))) if len(argv) > 2 and argv[2].isdigit() else 50
        offset = int(argv[3]) if len(argv) > 3 and argv[3].isdigit() else 0
        per = int(argv[4]) if len(argv) > 4 and argv[4].isdigit() and int(argv[4]) in PERIODS else 86400
        phrase = re.sub(r'[^\w@.:/ -]', '', argv[5])[:60] if len(argv) > 5 else ''
        phrase = '' if phrase == '-' else phrase
        out = listing(rows, offset, per, phrase)
    elif cmd == 'feed-update':
        out = feed_update(auto=len(argv) > 2 and argv[2] == 'auto')
        if out.get('updated'):
            os.system('/bin/pkill -HUP -f icap_server.py >/dev/null 2>&1')
    elif cmd == 'check':
        digest = (argv[2] if len(argv) > 2 else '').strip().lower()
        if not re.fullmatch(r'[0-9a-f]{64}', digest):
            out = {'error': 'a SHA-256 hash has 64 hexadecimal characters'}
        else:
            load_hashes(force=True)
            out = {'sha256': digest, 'known': is_known(digest), 'eicar': digest == EICAR_SHA256}
    elif cmd == 'prune':
        out = prune()
    else:
        out = {'error': 'unknown command'}
    print(json.dumps(out))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
