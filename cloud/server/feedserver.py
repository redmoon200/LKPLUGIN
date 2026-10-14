#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Feed server of os-layer7security (public port, no login).
#   GET  /feeds/<category>.txt        domain list (ETag / If-None-Match supported)
#   GET  /feeds/ip/<id>.txt           IP threat list
#   GET  /feeds/hashes/<algo>.txt     malware hashes (sha256, sha1, md5)
#   GET  /feeds/yara/index.json       signature files with checksums; /feeds/yara/<file>.yar
#   GET  /feeds/manifest.json         what was built and from where
#   POST /api/v1/checkin              a firewall reports in and learns the state of its license
#   POST /api/v1/trial                a 30 day trial key for a firewall (once per installation id)
#   GET  /health                      liveness probe
# Only whitelisted names are served; nothing else on disk is reachable. Every
# request is logged to the state database for the dashboard.

import argparse
import gzip
import hashlib
import http.server
import json
import os
import re
import socketserver
import threading
import time

import cloudcore
import store

CATEGORIES = ('ads', 'trackers', 'malware', 'phishing', 'adult', 'gambling', 'social', 'streaming', 'games', 'botnet')
NAME = re.compile(r'^/feeds/(?:(?:' + '|'.join(CATEGORIES) + r')\.txt|manifest\.json|ip2country-v[46]\.tsv\.gz'
                  r'|ip/(?:c2|compromised|attackers|drop|tor)\.txt|hashes/(?:sha256|sha1|md5)\.txt'
                  r'|yara/index\.json|yara/[A-Za-z0-9_.-]{1,80}\.yar)$')
STARTED = int(time.time())
MAX_BODY = 8192
RATE = {}                    # ip -> [timestamps] for the POST endpoints
RATE_LOCK = threading.Lock()


def rate_ok(ip, limit=20, window=60):
    now = time.time()
    with RATE_LOCK:
        lst = [t for t in RATE.get(ip, []) if now - t < window]
        lst.append(now)
        RATE[ip] = lst
        if len(RATE) > 5000:
            RATE.clear()
        return len(lst) <= limit


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'l7cloud/0.2'
    sys_version = ''
    root = '/var/lib/l7cloud/feeds'
    timeout = 20

    def _send(self, code, body=b'', ctype='text/plain; charset=utf-8', extra=None):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)
        try:
            store.log_request(self.client_address[0], self.command, self.path.split('?', 1)[0], code, len(body),
                              self.headers.get('User-Agent', ''))
        except Exception:                    # the log must never break an answer
            pass

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode(), 'application/json', {'Cache-Control': 'no-store'})

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path in ('/health', '/api/v1/health'):
            self._json(200, {'ok': True, 'uptime': int(time.time()) - STARTED})
            return
        if not NAME.match(path):
            self._send(404, b'not found\n')
            return
        fname = os.path.join(self.root, path[len('/feeds/'):])
        try:
            with open(fname, 'rb') as f:
                data = f.read()
        except OSError:
            self._send(404, b'not built yet\n')
            return
        etag = '"%s"' % hashlib.sha256(data).hexdigest()[:32]
        if self.headers.get('If-None-Match') == etag:
            self._send(304, b'', extra={'ETag': etag})
            return
        ctype = ('application/json' if path.endswith('.json') else
                 'application/gzip' if path.endswith('.gz') else 'text/plain; charset=utf-8')
        extra = {'ETag': etag, 'Cache-Control': 'max-age=300'}
        if len(data) > 4096 and not path.endswith('.gz') and 'gzip' in self.headers.get('Accept-Encoding', ''):
            data = gzip.compress(data, 6)
            extra['Content-Encoding'] = 'gzip'
        self._send(200, data, ctype, extra)

    def do_POST(self):
        path = self.path.split('?', 1)[0]
        ip = self.client_address[0]
        if path not in ('/api/v1/checkin', '/api/v1/trial'):
            self._json(404, {'ok': False, 'error': 'not found'})
            return
        if not rate_ok(ip):
            self._json(429, {'ok': False, 'error': 'too many requests'})
            return
        try:
            n = int(self.headers.get('Content-Length', '0'))
            if n <= 0 or n > MAX_BODY:
                raise ValueError
            data = json.loads(self.rfile.read(n).decode('utf-8', 'replace'))
            if not isinstance(data, dict):
                raise ValueError
        except (ValueError, OSError):
            self._json(400, {'ok': False, 'error': 'bad request'})
            return
        con = store.connect()
        try:
            res = cloudcore.checkin(con, ip, data) if path.endswith('checkin') else cloudcore.trial(con, ip, data)
        except Exception as exc:        # never leak internals to a client
            self.log_error('%r' % (exc,))
            res = {'ok': False, 'error': 'server error'}
        finally:
            con.close()
        self._json(200 if res.get('ok') else 400, res)

    def log_message(self, fmt, *args):
        print('%s %s' % (self.address_string(), fmt % args), flush=True)

    def log_request(self, code='-', size='-'):
        pass                                 # requests are written to the state database in _send


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 64


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bind', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=8080)
    ap.add_argument('--root', default='/var/lib/l7cloud/feeds')
    args = ap.parse_args()
    Handler.root = args.root
    cloudcore.ensure_keys()
    store.prune()
    Server((args.bind, args.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
