#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Sign-in sessions of the web access portal: who is signed in from which
# address, and the files / pf tables that make the firewall act on it.
#
#   auth.py sessions            JSON list of signed-in users
#   auth.py logout IP           sign one address out
#   auth.py logout-all          sign everybody out
#   auth.py log [ROWS]          recent sign-in events
#   auth.py status              counters for the GUI
#   auth.py sync                expire sessions and rewrite files and pf tables
#
# Signed-in addresses go to the pf table l7_auth_ok (together with the bypass
# list), to sessions.tsv (read by the engine: policies per user) and to one pf
# table per policy that names users (l7_usr_<id>).

import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import time

BASE = os.environ.get('L7_BASE', '/var/db/layer7security')
CONF_DIR = os.environ.get('L7_CONF_DIR', '/usr/local/etc/layer7security')
DB = os.path.join(BASE, 'auth.db')
PORTAL_JSON = os.path.join(CONF_DIR, 'portal.json')
USER_TABLES = os.path.join(CONF_DIR, 'user_tables.json')
SESSIONS_TSV = os.path.join(BASE, 'sessions.tsv')
OK_FILE = os.path.join(BASE, 'auth_ok.txt')
ENGINE_DB = os.path.join(BASE, 'l7.db')
PFCTL = '/sbin/pfctl'
KEEP_LOG_DAYS = 90

SCHEMA = """CREATE TABLE IF NOT EXISTS sessions(
  ip TEXT PRIMARY KEY, user TEXT NOT NULL, mac TEXT, started INTEGER, last_active INTEGER, expires INTEGER);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, type TEXT, user TEXT, ip TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);"""


def now():
    return int(time.time())


def config():
    try:
        with open(PORTAL_JSON) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def connect():
    os.makedirs(BASE, exist_ok=True)
    con = sqlite3.connect(DB, timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    try:
        os.chmod(DB, 0o600)
    except OSError:
        pass
    return con


def clean(text, limit=80):
    return re.sub(r'[\x00-\x1f\x7f]', '', str(text or ''))[:limit]


def valid_ip(text):
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def log_event(con, kind, user='', ip='', detail=''):
    con.execute('INSERT INTO events(ts,type,user,ip,detail) VALUES(?,?,?,?,?)',
                (now(), kind, clean(user, 64), clean(ip, 64), clean(detail, 160)))


def login(ip, user, mac='', hours=None):
    """create or replace the session of an address; returns the session dict"""
    cfg = config()
    ip = valid_ip(ip)
    if not ip:
        raise ValueError('bad address')
    hours = hours or int(cfg.get('sessionHours', 8))
    t = now()
    con = connect()
    with con:
        con.execute('REPLACE INTO sessions(ip,user,mac,started,last_active,expires) VALUES(?,?,?,?,?,?)',
                    (ip, clean(user, 64), clean(mac, 17), t, t, t + hours * 3600))
        log_event(con, 'login', user, ip, 'signed in')
    con.close()
    sync()
    return {'ip': ip, 'user': user, 'expires': t + hours * 3600}


def kill_states(ip):
    """drop the open connections of a device that is no longer signed in"""
    ip = valid_ip(ip)
    if ip:
        try:
            subprocess.run([PFCTL, '-k', ip], capture_output=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            pass


def logout(ip, reason='logout', detail=''):
    ip = valid_ip(ip)
    if not ip:
        return False
    con = connect()
    with con:
        row = con.execute('SELECT user FROM sessions WHERE ip=?', (ip,)).fetchone()
        if row is not None:
            con.execute('DELETE FROM sessions WHERE ip=?', (ip,))
            log_event(con, reason, row['user'], ip, detail)
    con.close()
    if row is None:
        return False
    sync()
    kill_states(ip)
    return True


def session_of(ip):
    con = connect()
    row = con.execute('SELECT * FROM sessions WHERE ip=?', (ip,)).fetchone()
    con.close()
    return dict(row) if row else None


def sessions():
    con = connect()
    rows = [dict(r) for r in con.execute('SELECT ip,user,mac,started,last_active,expires FROM sessions ORDER BY started DESC')]
    con.close()
    return rows


def last_activity(ips):
    """newest engine flow time per client address (idle detection)"""
    out = {}
    if not ips or not os.path.exists(ENGINE_DB):
        return out
    try:
        con = sqlite3.connect('file:%s?mode=ro' % ENGINE_DB, uri=True, timeout=5)
        for i in range(0, len(ips), 300):
            chunk = ips[i:i + 300]
            q = 'SELECT client, MAX(ts_end) FROM flows WHERE client IN (%s) AND ts_end >= ? GROUP BY client' % ','.join('?' * len(chunk))
            for client, ts in con.execute(q, chunk + [now() - 86400]):
                out[client] = ts
        con.close()
    except sqlite3.Error:
        pass
    return out


def expire():
    """end sessions that ran out or have been idle too long"""
    cfg = config()
    idle = int(cfg.get('idleMinutes', 0)) * 60
    t = now()
    con = connect()
    rows = [dict(r) for r in con.execute('SELECT ip,user,started,last_active,expires FROM sessions')]
    act = last_activity([r['ip'] for r in rows]) if idle else {}
    gone = []
    with con:
        for r in rows:
            last = max(r['last_active'], act.get(r['ip'], 0))
            if last > r['last_active']:
                con.execute('UPDATE sessions SET last_active=? WHERE ip=?', (last, r['ip']))
            if r['expires'] <= t:
                gone.append((r, 'expire', 'session time is over'))
            elif idle and t - last > idle:
                gone.append((r, 'expire', 'idle for %d minutes' % ((t - last) // 60)))
        for r, kind, why in gone:
            con.execute('DELETE FROM sessions WHERE ip=?', (r['ip'],))
            log_event(con, kind, r['user'], r['ip'], why)
        con.execute('DELETE FROM events WHERE ts < ?', (t - KEEP_LOG_DAYS * 86400,))
    con.close()
    if gone:
        sync()
        for r, _kind, _why in gone:
            kill_states(r['ip'])
    return len(gone)


def write_file(path, text):
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def pf_replace(table, path):
    try:
        subprocess.run([PFCTL, '-q', '-t', table, '-T', 'replace', '-f', path], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        pass


def sync():
    """rewrite sessions.tsv, auth_ok.txt and the per-policy user tables from the database"""
    rows = sessions()
    cfg = config()
    write_file(SESSIONS_TSV, ''.join('%s\t%s\n' % (r['ip'], clean(r['user'], 48).replace('\t', ' ')) for r in rows))
    ips = []
    for r in rows:
        ips.append(r['ip'])
    for net in cfg.get('bypass', []):
        try:
            ips.append(str(ipaddress.ip_network(net, strict=False)))
        except ValueError:
            pass
    write_file(OK_FILE, ''.join(i + '\n' for i in sorted(set(ips))))
    pf_replace('l7_auth_ok', OK_FILE)
    try:
        with open(USER_TABLES) as f:
            mapping = json.load(f)       # {"policy id": ["user", ...]}
    except (OSError, ValueError):
        mapping = {}
    for pid, users in mapping.items():
        if not str(pid).isdigit():
            continue
        wanted = {u.lower() for u in users}
        path = os.path.join(BASE, 'usr_%s.txt' % pid)
        write_file(path, ''.join(r['ip'] + '\n' for r in rows if r['user'].lower() in wanted))
        pf_replace('l7_usr_%s' % pid, path)
    # the engine rereads sessions.tsv on its own (it watches the file)


def recent_log(rows=100):
    con = connect()
    out = [dict(r) for r in con.execute('SELECT ts,type,user,ip,detail FROM events ORDER BY id DESC LIMIT ?', (rows,))]
    con.close()
    return out


def status():
    con = connect()
    day = now() - 86400
    n = con.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]
    ev = {r[0]: r[1] for r in con.execute('SELECT type, COUNT(*) FROM events WHERE ts >= ? GROUP BY type', (day,))}
    con.close()
    return {'active': n, 'logins24h': ev.get('login', 0), 'failures24h': ev.get('fail', 0) + ev.get('lockout', 0),
            'expired24h': ev.get('expire', 0), 'logouts24h': ev.get('logout', 0) + ev.get('admin-logout', 0)}


def main(argv):
    cmd = argv[1] if len(argv) > 1 else 'status'
    if cmd == 'sessions':
        out = {'rows': sessions(), 'ts': now()}
    elif cmd == 'logout' and len(argv) > 2:
        out = {'ok': logout(argv[2], 'admin-logout', 'signed out by an administrator')}
    elif cmd == 'logout-all':
        n = 0
        for r in sessions():
            n += 1 if logout(r['ip'], 'admin-logout', 'signed out by an administrator') else 0
        out = {'ok': True, 'count': n}
    elif cmd == 'log':
        rows = int(argv[2]) if len(argv) > 2 and argv[2].isdigit() else 100
        out = {'rows': recent_log(max(1, min(rows, 500)))}
    elif cmd == 'sync':
        out = {'expired': expire()}
        sync()
    else:
        out = status()
    print(json.dumps(out))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
