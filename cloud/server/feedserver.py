#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Minimal read-only feed server for os-layer7security.
#   GET /feeds/<category>.txt   domain list (ETag / If-None-Match supported)
#   GET /feeds/manifest.json    what was built and from where
#   GET /health                 liveness probe
# Only whitelisted category names are served; nothing else on disk is reachable.

import argparse
import hashlib
import http.server
import json
import os
import re
import socketserver
import time

CATEGORIES = ('ads', 'trackers', 'malware', 'phishing', 'adult', 'gambling', 'social', 'streaming', 'games')
NAME = re.compile(r'^/feeds/(?:(?:' + '|'.join(CATEGORIES) + r')\.txt|manifest\.json|ip2country-v[46]\.tsv\.gz)$')
STARTED = int(time.time())


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'l7cloud/0.1'
    root = '/var/lib/l7cloud/feeds'

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

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path == '/health':
            self._send(200, json.dumps({'ok': True, 'uptime': int(time.time()) - STARTED}).encode(),
                       'application/json')
            return
        if not NAME.match(path):
            self._send(404, b'not found\n')
            return
        fname = os.path.join(self.root, os.path.basename(path))
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
        self._send(200, data, ctype, {'ETag': etag, 'Cache-Control': 'max-age=300'})

    def log_message(self, fmt, *args):
        print('%s %s' % (self.address_string(), fmt % args), flush=True)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bind', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=8080)
    ap.add_argument('--root', default='/var/lib/l7cloud/feeds')
    args = ap.parse_args()
    Handler.root = args.root
    Server((args.bind, args.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
