#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Dashboard of the cloud server (admin port, login required): feed health and
# builds, the firewalls that checked in, the license generator, activity.
#
#   dashboard.py serve [--port 8090] [--bind 0.0.0.0]
#   dashboard.py init                 create the signing key and the admin password (printed once)
#   dashboard.py set-password         set a new admin password from the terminal
#   dashboard.py pubkey               print the public key (PEM) that the plugin embeds

import argparse
import calendar
import csv
import getpass
import http.server
import io
import json
import os
import re
import secrets
import socketserver
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlsplit

import cloudcore
import licenselib
import store

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, 'dashboard.html')
DATA_DIR = os.environ.get('L7_CLOUD_DATA', os.path.join(HERE, '..', 'data'))
SESSION_HOURS = 8
MAX_BODY = 16384
LOGIN_LIMIT = 5


def cleanup_sessions(con):
    with con:
        con.execute('DELETE FROM sessions WHERE expires < ?', (int(time.time()),))


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'l7dash'
    sys_version = ''
    timeout = 30

    def log_message(self, fmt, *args):
        pass

    # ----- helpers
    def send(self, code, body, ctype='application/json', headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def cookie_token(self):
        for part in (self.headers.get('Cookie') or '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == 'l7cs':
                return v
        return ''

    def session_ok(self, con):
        tok = self.cookie_token()
        if not re.fullmatch(r'[0-9a-f]{48}', tok or ''):
            return False
        row = con.execute('SELECT expires FROM sessions WHERE token=?', (tok,)).fetchone()
        return bool(row and row['expires'] > time.time())

    def body(self):
        try:
            n = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY:
            return {}
        try:
            data = json.loads(self.rfile.read(n).decode('utf-8', 'replace'))
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}

    # ----- routing
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlsplit(self.path)
        if u.path in ('/', '/index.html'):
            try:
                with open(PAGE, 'rb') as f:
                    self.send(200, f.read(), 'text/html; charset=utf-8')
            except OSError:
                self.send(500, b'dashboard.html is missing', 'text/plain')
            return
        if not u.path.startswith('/api/'):
            self.send(404, {'error': 'not found'})
            return
        con = store.connect()
        try:
            if u.path == '/api/me':
                self.send(200, {'auth': self.session_ok(con), 'configured': store.get_setting(con, 'admin_hash') is not None})
                return
            if not self.session_ok(con):
                self.send(401, {'error': 'sign in'})
                return
            self.route_get(con, u.path, parse_qs(u.query))
        finally:
            con.close()

    def route_get(self, con, path, q):
        if path == '/api/overview':
            self.send(200, cloudcore.overview(con))
        elif path == '/api/feeds':
            manifest = cloudcore.read_json(os.path.join(cloudcore.FEEDS, 'manifest.json'), {})
            status = cloudcore.read_json(cloudcore.BUILD_STATUS, {})
            self.send(200, {'files': cloudcore.feed_files(), 'history': status.get('history', []), 'manifest': manifest,
                            'running': cloudcore.build_running()})
        elif path == '/api/build/log':
            try:
                with open(cloudcore.BUILD_LOG, errors='replace') as f:
                    lines = f.read().splitlines()[-200:]
            except OSError:
                lines = []
            self.send(200, {'lines': lines, 'running': cloudcore.build_running()})
        elif path == '/api/firewalls':
            self.send(200, {'rows': cloudcore.clients(con)})
        elif path == '/api/licenses':
            self.send(200, {'rows': cloudcore.licenses(con)})
        elif path == '/api/licenses.csv':
            out = io.StringIO()
            w = csv.writer(out)
            w.writerow(['key_id', 'type', 'customer', 'state', 'issued', 'expires', 'bound_to', 'source', 'note', 'key'])
            for r in cloudcore.licenses(con):
                w.writerow([r['key_id'], r['type'], r['customer'], r['state'], time.strftime('%Y-%m-%d', time.gmtime(r['issued'])),
                            '' if r['expires'] is None else time.strftime('%Y-%m-%d', time.gmtime(r['expires'])),
                            r['bound_install'], r['source'], r['note'], r['key']])
            self.send(200, out.getvalue(), 'text/csv; charset=utf-8', {'Content-Disposition': 'attachment; filename="licenses.csv"'})
        elif path == '/api/activity':
            try:
                limit = max(1, min(500, int((q.get('limit') or ['100'])[0])))
            except ValueError:
                limit = 100
            kind = (q.get('kind') or [''])[0]
            where, args = '1=1', []
            if kind == 'feeds':
                where = "path LIKE '/feeds/%'"
            elif kind == 'api':
                where = "path LIKE '/api/%'"
            elif kind == 'errors':
                where = 'status >= 400'
            rows = [dict(r) for r in con.execute('SELECT ts, ip, method, path, status, bytes, ua FROM requests WHERE ' + where +
                                                 ' ORDER BY id DESC LIMIT ?', args + [limit])]
            self.send(200, {'rows': rows})
        elif path == '/api/pubkey':
            pem = cloudcore.public_pem()
            self.send(200, {'pem': pem, 'b64': licenselib.public_b64(pem)})
        elif path == '/api/settings':
            self.send(200, {'trials_enabled': store.get_setting(con, 'trials_enabled', '1') == '1'})
        else:
            self.send(404, {'error': 'not found'})

    def do_POST(self):
        u = urlsplit(self.path)
        if self.headers.get('X-Requested-With') != 'l7dash':
            self.send(403, {'error': 'forbidden'})
            return
        data = self.body()
        con = store.connect()
        try:
            if u.path == '/api/login':
                self.login(con, data)
                return
            if not self.session_ok(con):
                self.send(401, {'error': 'sign in'})
                return
            self.route_post(con, u.path, data)
        except ValueError as exc:
            self.send(400, {'error': str(exc)})
        except Exception as exc:
            sys.stderr.write('dashboard error: %r\n' % (exc,))
            self.send(500, {'error': 'server error'})
        finally:
            con.close()

    def login(self, con, data):
        ip = self.client_address[0]
        recent = con.execute('SELECT COUNT(*) FROM logins WHERE ip=? AND ok=0 AND ts >= ?', (ip, int(time.time()) - 600)).fetchone()[0]
        if recent >= LOGIN_LIMIT:
            self.send(429, {'error': 'Too many wrong attempts. Try again in a few minutes.'})
            return
        stored = store.get_setting(con, 'admin_hash')
        ok = bool(stored) and store.check_password(str(data.get('password', ''))[:200], stored)
        with con:
            con.execute('INSERT INTO logins(ts,ip,ok) VALUES(?,?,?)', (int(time.time()), ip, 1 if ok else 0))
        if not ok:
            self.send(401, {'error': 'Wrong password.'})
            return
        cleanup_sessions(con)
        tok = secrets.token_hex(24)
        with con:
            con.execute('INSERT INTO sessions(token,created,expires,ip) VALUES(?,?,?,?)',
                        (tok, int(time.time()), int(time.time()) + SESSION_HOURS * 3600, ip))
        self.send(200, {'ok': True}, headers={'Set-Cookie': 'l7cs=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d' % (tok, SESSION_HOURS * 3600)})

    def route_post(self, con, path, d):
        if path == '/api/logout':
            with con:
                con.execute('DELETE FROM sessions WHERE token=?', (self.cookie_token(),))
            self.send(200, {'ok': True}, headers={'Set-Cookie': 'l7cs=; Path=/; Max-Age=0'})
        elif path == '/api/build':
            if cloudcore.build_running():
                raise ValueError('A build is already running.')
            only = ','.join(x for x in str(d.get('only', '')).split(',') if x in ('domains', 'ips', 'hashes', 'yara', 'geoip'))
            cmd = [sys.executable, os.path.join(HERE, 'build_feeds.py'), '--data', DATA_DIR]
            if only:
                cmd += ['--only', only]
            log = open(cloudcore.BUILD_LOG, 'w')
            subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True, cwd=HERE)
            self.send(200, {'ok': True})
        elif path == '/api/licenses/issue':
            issued = None
            if d.get('issued'):
                try:
                    issued = calendar.timegm(time.strptime(str(d['issued'])[:10], '%Y-%m-%d'))
                except ValueError:
                    raise ValueError('The issue date looks like 2026-10-14.')
            customer = cloudcore.clean(d.get('customer', ''))
            if not customer:
                raise ValueError('Enter the customer name.')
            info = cloudcore.issue_license(con, str(d.get('type', '')), customer, d.get('note', ''), str(d.get('install_id', '')), issued)
            self.send(200, {'ok': True, 'license': info})
        elif path == '/api/licenses/revoke':
            key_id = str(d.get('key_id', ''))
            if not re.fullmatch(r'[0-9A-F]{16}', key_id) or not cloudcore.set_revoked(con, key_id, bool(d.get('revoked', True))):
                raise ValueError('Unknown license.')
            self.send(200, {'ok': True})
        elif path == '/api/licenses/replace':
            key_id = str(d.get('key_id', ''))
            if not re.fullmatch(r'[0-9A-F]{16}', key_id):
                raise ValueError('Unknown license.')
            info = cloudcore.replace_license(con, key_id, str(d.get('type', '')), str(d.get('install_id', '')))
            self.send(200, {'ok': True, 'license': info})
        elif path == '/api/settings':
            if 'trials_enabled' in d:
                store.set_setting(con, 'trials_enabled', '1' if d['trials_enabled'] else '0')
            self.send(200, {'ok': True})
        elif path == '/api/password':
            stored = store.get_setting(con, 'admin_hash')
            new = str(d.get('new', ''))
            if not store.check_password(str(d.get('old', '')), stored or ''):
                raise ValueError('The current password is wrong.')
            if len(new) < 10:
                raise ValueError('Use at least 10 characters.')
            store.set_setting(con, 'admin_hash', store.hash_password(new))
            with con:
                con.execute('DELETE FROM sessions')
            self.send(200, {'ok': True}, headers={'Set-Cookie': 'l7cs=; Path=/; Max-Age=0'})
        else:
            self.send(404, {'error': 'not found'})


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 32


def init():
    pub = cloudcore.ensure_keys()
    con = store.connect()
    if store.get_setting(con, 'admin_hash') is None:
        password = secrets.token_urlsafe(12)
        store.set_setting(con, 'admin_hash', store.hash_password(password))
        print('Dashboard password (shown once): ' + password)
    else:
        print('Dashboard password is already set (dashboard.py set-password changes it).')
    print('Public key for the plugin (License.php):')
    print(licenselib.public_b64(pub))
    con.close()


def set_password():
    con = store.connect()
    pw = getpass.getpass('New dashboard password (10+ characters): ')
    if len(pw) < 10 or pw != getpass.getpass('Again: '):
        print('Not changed.')
        return 1
    store.set_setting(con, 'admin_hash', store.hash_password(pw))
    print('Changed.')
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', choices=['serve', 'init', 'set-password', 'pubkey'])
    ap.add_argument('--bind', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=8090)
    a = ap.parse_args()
    if a.cmd == 'init':
        init()
    elif a.cmd == 'set-password':
        return set_password()
    elif a.cmd == 'pubkey':
        cloudcore.ensure_keys()
        print(cloudcore.public_pem(), end='')
    else:
        cloudcore.ensure_keys()
        con = store.connect()
        if store.get_setting(con, 'admin_hash') is None:
            print('No dashboard password yet: run "dashboard.py init" first.', file=sys.stderr)
            return 2
        con.close()
        Server((a.bind, a.port), Handler).serve_forever()
    return 0


if __name__ == '__main__':
    sys.exit(main())
