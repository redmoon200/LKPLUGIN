#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Tamper-evident audit log for AI service use and content inspection.
#
# Every record stores the SHA-256 of (previous hash + canonical record), so any
# edit, deletion or reordering breaks the chain from that point on. Records are
# appended inside an IMMEDIATE transaction, so several writers (the ingest job,
# the ICAP server) can share one chain. Snippets are masked at the source and
# masked again here; raw content is never stored.
#
#   audit.py ingest                              engine events -> chain
#   audit.py list ROWS OFFSET PERIOD KIND PHRASE USER
#   audit.py verify USER
#   audit.py export csv|json|jsonl PERIOD USER
#   audit.py verify-file PATH                    verify an exported json/jsonl
#   audit.py prune                               apply the retention period
#   audit.py status
#   audit.py access USER WHAT                    record a view/export/ack
#
# A hash chain proves integrity only against someone who cannot rewrite the
# whole file; the remote syslog target is the independent copy.

import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import socket
import sqlite3
import sys
import time

try:
    import syslog
except ImportError:     # not on every platform (the firewall has it)
    syslog = None
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dlp_rules  # noqa: E402

AUDIT_DB = os.environ.get('L7_AUDIT_DB', '/var/db/layer7security/audit.db')
ENGINE_DB = os.environ.get('L7_ENGINE_DB', '/var/db/layer7security/l7.db')
CONFIG = os.environ.get('L7_CONFIG', '/conf/config.xml')
CATALOG = os.environ.get('L7_AI_CATALOG', '/usr/local/share/layer7security/ai_services.json')
GENESIS = '0' * 64
PERIODS = (300, 3600, 21600, 86400, 604800, 2592000, 31536000)
FIELDS = ('seq', 'ts', 'source', 'kind', 'action', 'client', 'user', 'service', 'host', 'category', 'detail', 'count')
MAX_DETAIL = 240

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY, ts INTEGER NOT NULL, source TEXT, kind TEXT, action TEXT, client TEXT, user TEXT,
  service TEXT, host TEXT, category TEXT, detail TEXT, count INTEGER, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""


def config():
    """audit settings from config.xml (defaults when absent)"""
    out = {'enabled': False, 'retention': 365, 'syslogLocal': True, 'syslogTarget': '',
           'privacyAckBy': '', 'privacyAckAt': '', 'users': []}
    try:
        root = ET.parse(CONFIG).getroot().find('./OPNsense/layer7security')
    except (OSError, ET.ParseError):
        return out
    if root is None:
        return out
    node = root.find('audit')
    if node is not None:
        g = {c.tag: (c.text or '') for c in node}
        out['enabled'] = g.get('enabled') == '1'
        try:
            out['retention'] = max(1, int(g.get('retentionDays') or 365))
        except ValueError:
            pass
        out['syslogLocal'] = g.get('syslogLocal', '1') != '0'
        out['syslogTarget'] = g.get('syslogTarget', '').strip()
        out['privacyAckBy'] = g.get('privacyAckBy', '')
        out['privacyAckAt'] = g.get('privacyAckAt', '')
    for u in root.findall('./users/user'):
        name = (u.findtext('name') or '').strip()
        for addr in (u.findtext('addresses') or '').split(','):
            addr = addr.strip()
            if addr and name:
                try:
                    out['users'].append((ipaddress.ip_network(addr, strict=False), name))
                except ValueError:
                    pass
    return out


def user_for(cfg, ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ''
    for net, name in cfg['users']:
        if a.version == net.version and a in net:
            return name
    return ''


def connect():
    new = not os.path.exists(AUDIT_DB)
    os.makedirs(os.path.dirname(AUDIT_DB), exist_ok=True)
    con = sqlite3.connect(AUDIT_DB, timeout=15, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA journal_mode=WAL')
    con.executescript(SCHEMA)
    if new:
        try:
            os.chmod(AUDIT_DB, 0o600)
        except OSError:
            pass
    return con


def meta_get(con, key, default=''):
    row = con.execute('SELECT v FROM meta WHERE k=?', (key,)).fetchone()
    return row[0] if row else default


def meta_set(con, key, value):
    con.execute('INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', (key, str(value)))


def sanitize(text):
    """no control characters, masked again, bounded"""
    text = re.sub(r'[\x00-\x1f\x7f]+', ' ', str(text or ''))
    text = dlp_rules.mask_text(text)
    return text[:MAX_DETAIL]


def canonical(rec):
    return json.dumps({k: rec[k] for k in FIELDS}, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def chain_hash(prev, rec):
    return hashlib.sha256((prev + canonical(rec)).encode()).hexdigest()


def emit_syslog(cfg, rec, digest):
    line = json.dumps(dict({k: rec[k] for k in FIELDS}, hash=digest), sort_keys=True, ensure_ascii=True)
    if cfg['syslogLocal'] and syslog is not None:
        try:
            syslog.openlog('l7ai-audit', 0, syslog.LOG_LOCAL5)
            syslog.syslog(syslog.LOG_INFO, line)
        except OSError:
            pass
    target = cfg['syslogTarget']
    if target:
        host, _, port = target.partition(':')
        try:
            stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(rec['ts']))
            msg = '<174>1 %s %s l7ai-audit - - - %s' % (stamp, socket.gethostname(), line)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.sendto(msg.encode('utf-8'), (host, int(port) if port.isdigit() else 514))
        except (OSError, ValueError):
            pass


def append(kind, action, client='', user='', service='', host='', category='', detail='', count=1,
           source='engine', ts=None, cfg=None, force=False):
    """add one record; returns (seq, hash) or None when auditing is disabled"""
    cfg = cfg or config()
    if not cfg['enabled'] and not force:
        return None
    con = connect()
    try:
        con.execute('BEGIN IMMEDIATE')
        row = con.execute('SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
        if row:
            seq, prev = row['seq'] + 1, row['hash']
        else:
            seq, prev = int(meta_get(con, 'base_seq', 0)) + 1, meta_get(con, 'base_hash', GENESIS)
        rec = {'seq': seq, 'ts': int(ts or time.time()), 'source': str(source)[:24], 'kind': str(kind)[:32],
               'action': str(action)[:32], 'client': str(client)[:64], 'user': str(user)[:64],
               'service': str(service)[:48], 'host': str(host)[:128][:128], 'category': str(category)[:32],
               'detail': sanitize(detail), 'count': int(count)}
        digest = chain_hash(prev, rec)
        con.execute('INSERT INTO audit(%s, prev_hash, hash) VALUES(%s)' % (','.join(FIELDS), ','.join('?' * (len(FIELDS) + 2))),
                    [rec[k] for k in FIELDS] + [prev, digest])
        meta_set(con, 'head_seq', seq)
        meta_set(con, 'head_hash', digest)
        con.execute('COMMIT')
    except Exception:
        try:
            con.execute('ROLLBACK')
        except sqlite3.Error:
            pass
        raise
    finally:
        con.close()
    emit_syslog(cfg, rec, digest)
    return seq, digest


def catalog_names():
    try:
        with open(CATALOG) as f:
            return {x['id']: x['name'] for x in json.load(f)}
    except (OSError, ValueError, KeyError):
        return {}


def ingest():
    """copy new AI events of the engine into the chain"""
    cfg = config()
    if not cfg['enabled'] or not os.path.exists(ENGINE_DB):
        return {'ingested': 0, 'enabled': cfg['enabled']}
    names = catalog_names()
    con = connect()
    mark = meta_get(con, 'engine_event_id', '')
    eng = sqlite3.connect('file:%s?mode=ro' % ENGINE_DB, uri=True, timeout=10)
    eng.row_factory = sqlite3.Row
    if mark == '':
        # first run since auditing was enabled: start from now, never import older history
        meta_set(con, 'engine_event_id', eng.execute('SELECT COALESCE(MAX(id), 0) FROM events').fetchone()[0])
        con.close()
        eng.close()
        return {'ingested': 0, 'enabled': True, 'initialised': True}
    mark = int(mark)
    con.close()
    # the engine's event numbers start again when its table was emptied (retention, new database): follow it
    top = eng.execute('SELECT COALESCE(MAX(id), 0) FROM events').fetchone()[0]
    reset = mark > top
    if reset:
        mark = 0
    rows = eng.execute("SELECT id, ts, type, client, server, app, category, host, policy, detail FROM events"
                       " WHERE id > ? AND type IN ('ai-use','ai-block') ORDER BY id LIMIT 5000", (mark,)).fetchall()
    last = mark
    for r in rows:
        blocked = r['type'] == 'ai-block'
        append(r['type'], 'blocked' if blocked else 'observed', client=r['client'], user=user_for(cfg, r['client']),
               service=names.get(r['app'], r['app']), host=r['host'], category='ai-service',
               detail='%s; policy: %s' % (r['detail'], r['policy']), ts=r['ts'], cfg=cfg)
        last = r['id']
    eng.close()
    if last != mark or reset:
        con = connect()
        meta_set(con, 'engine_event_id', last)
        con.close()
    return {'ingested': len(rows), 'enabled': True}


def verify_rows(rows, prev, expect_seq=None):
    """walk records; returns dict(ok, records, head, bad_seq, reason)"""
    count = 0
    for r in rows:
        if expect_seq is not None and r['seq'] != expect_seq:
            return {'ok': False, 'records': count, 'bad_seq': r['seq'],
                    'reason': 'sequence gap: expected %d (records removed or reordered)' % expect_seq}
        if r['prev_hash'] != prev:
            return {'ok': False, 'records': count, 'bad_seq': r['seq'], 'reason': 'broken link to the previous record'}
        if chain_hash(prev, r) != r['hash']:
            return {'ok': False, 'records': count, 'bad_seq': r['seq'], 'reason': 'record content does not match its hash'}
        prev = r['hash']
        count += 1
        if expect_seq is not None:
            expect_seq += 1
    return {'ok': True, 'records': count, 'head': prev}


def verify():
    con = connect()
    base_seq = int(meta_get(con, 'base_seq', 0))
    base_hash = meta_get(con, 'base_hash', GENESIS)
    rows = con.execute('SELECT * FROM audit ORDER BY seq').fetchall()
    res = verify_rows(rows, base_hash, base_seq + 1)
    if res['ok']:
        head_seq = int(meta_get(con, 'head_seq', 0))
        last = rows[-1]['seq'] if rows else base_seq
        if head_seq > last:
            res.update({'ok': False, 'bad_seq': last + 1,
                        'reason': 'records at the end are missing (expected up to %d)' % head_seq})
    res['base_seq'] = base_seq
    con.close()
    return res


def verify_file(path):
    try:
        with open(path, encoding='utf-8') as f:
            text = f.read()
    except OSError as exc:
        return {'ok': False, 'reason': str(exc)}
    try:
        data = json.loads(text)
        recs = data['records'] if isinstance(data, dict) else data
    except ValueError:
        recs = [json.loads(l) for l in text.splitlines() if l.strip()]
    if not recs:
        return {'ok': True, 'records': 0}
    return verify_rows(recs, recs[0]['prev_hash'], recs[0]['seq']) | {'first_seq': recs[0]['seq']}


def period(value, default=86400):
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    return v if v in PERIODS else default


def listing(rows, offset, per, kind, phrase):
    con = connect()
    where, args = ['ts >= ?'], [int(time.time()) - per]
    if kind and kind != '-' and re.match(r'^[a-z-]{1,32}$', kind):
        where.append('kind = ?')
        args.append(kind)
    if phrase and phrase != '-' and re.match(r'^[A-Za-z0-9._:/@ -]{1,64}$', phrase):
        like = '%' + phrase + '%'
        where.append('(client LIKE ? OR user LIKE ? OR service LIKE ? OR host LIKE ? OR detail LIKE ? OR kind LIKE ?)')
        args += [like] * 6
    cond = ' AND '.join(where)
    total = con.execute('SELECT COUNT(*) FROM audit WHERE ' + cond, args).fetchone()[0]
    data = [dict(r) for r in con.execute('SELECT * FROM audit WHERE ' + cond + ' ORDER BY seq DESC LIMIT ? OFFSET ?',
                                         args + [rows, offset]).fetchall()]
    con.close()
    return {'rows': data, 'total': total}


def export(fmt, per):
    con = connect()
    rows = [dict(r) for r in con.execute('SELECT * FROM audit WHERE ts >= ? ORDER BY seq',
                                         (int(time.time()) - per,)).fetchall()]
    head = meta_get(con, 'head_hash', GENESIS)
    con.close()
    if fmt == 'csv':
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator='\n')
        cols = list(FIELDS) + ['prev_hash', 'hash']
        w.writerow(cols)
        for r in rows:
            w.writerow([(chr(9) + r[c]) if isinstance(r[c], str) and r[c] and r[c][0] in '=+-@' else r[c] for c in cols])
        return buf.getvalue()
    if fmt == 'jsonl':
        return '\n'.join(json.dumps(r, sort_keys=True) for r in rows) + ('\n' if rows else '')
    manifest = {'exported': int(time.time()), 'records': len(rows), 'head_hash': head,
                'algorithm': 'sha256(prev_hash + canonical_json(record))', 'fields': list(FIELDS)}
    return json.dumps({'manifest': manifest, 'records': rows}, indent=1, sort_keys=True)


def prune():
    cfg = config()
    cutoff = int(time.time()) - cfg['retention'] * 86400
    con = connect()
    try:
        con.execute('BEGIN IMMEDIATE')
        last = con.execute('SELECT seq, hash FROM audit WHERE ts < ? ORDER BY seq DESC LIMIT 1', (cutoff,)).fetchone()
        if not last:
            con.execute('COMMIT')
            return {'pruned': 0}
        n = con.execute('DELETE FROM audit WHERE seq <= ?', (last['seq'],)).rowcount
        meta_set(con, 'base_seq', last['seq'])
        meta_set(con, 'base_hash', last['hash'])
        con.execute('COMMIT')
    except Exception:
        con.execute('ROLLBACK')
        raise
    finally:
        con.close()
    append('audit-prune', 'retention', source='audit', detail='%d records older than %d days removed' % (n, cfg['retention']),
           count=n, cfg=cfg, force=True)
    return {'pruned': n}


def status():
    cfg = config()
    info = {'enabled': cfg['enabled'], 'retention': cfg['retention'], 'syslogLocal': cfg['syslogLocal'],
            'syslogTarget': cfg['syslogTarget'], 'privacyAckBy': cfg['privacyAckBy'], 'privacyAckAt': cfg['privacyAckAt'],
            'records': 0, 'head': GENESIS, 'last': 0, 'size': 0}
    if os.path.exists(AUDIT_DB):
        con = connect()
        info['records'] = con.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
        info['head'] = meta_get(con, 'head_hash', GENESIS)
        row = con.execute('SELECT MAX(ts) FROM audit').fetchone()
        info['last'] = row[0] or 0
        con.close()
        info['size'] = os.path.getsize(AUDIT_DB)
    return info


def access(user, what):
    """who looked at, exported or verified the audit log is itself recorded"""
    user = re.sub(r'[^A-Za-z0-9_.@-]', '', user)[:64] or 'unknown'
    what = re.sub(r'[^a-z-]', '', what)[:32] or 'view'
    if what == 'view' and os.path.exists(AUDIT_DB):
        con = connect()
        last = con.execute("SELECT MAX(ts) FROM audit WHERE kind='audit-access' AND action='view' AND user=?",
                           (user,)).fetchone()[0]
        con.close()
        if last and time.time() - last < 300:
            return {'recorded': False}
    res = append('audit-access', what, user=user, source='audit', detail='audit log %s by %s' % (what, user), force=True)
    return {'recorded': bool(res)}


def main():
    a = sys.argv[1:]
    cmd = a[0] if a else 'status'
    if cmd == 'ingest':
        out = ingest()
    elif cmd == 'list':
        rows = max(1, min(500, int(a[1]))) if len(a) > 1 and a[1].isdigit() else 25
        offset = int(a[2]) if len(a) > 2 and a[2].isdigit() else 0
        out = listing(rows, offset, period(a[3] if len(a) > 3 else 0), a[4] if len(a) > 4 else '-', a[5] if len(a) > 5 else '-')
    elif cmd == 'verify':
        out = verify()
    elif cmd == 'verify-file':
        out = verify_file(a[1] if len(a) > 1 else '')
    elif cmd == 'export':
        fmt = a[1] if len(a) > 1 and a[1] in ('csv', 'json', 'jsonl') else 'json'
        sys.stdout.write(export(fmt, period(a[2] if len(a) > 2 else 0)))
        return
    elif cmd == 'prune':
        out = prune()
    elif cmd == 'access':
        out = access(a[1] if len(a) > 1 else '', a[2] if len(a) > 2 else 'view')
    else:
        out = status()
    print(json.dumps(out))


if __name__ == '__main__':
    main()
