#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Web access sign-in portal. Devices that are not signed in cannot browse: their
# plain HTTP requests are redirected here (pf rdr to 127.0.0.1:8081), HTTPS to
# the internet is blocked until they sign in on the HTTPS login page. Passwords
# are checked by OPNsense itself (local users, LDAP, RADIUS ...), see authcheck.php.
#
#   portal.py            run both listeners (started by rc.d/layer7security_portal)
#
# Settings: /usr/local/etc/layer7security/portal.json (written by apply.php).

import hashlib
import hmac
import html
import http.server
import ipaddress
import json
import os
import re
import secrets
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, quote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import auth  # noqa: E402

PORTAL_DIR = os.path.join(auth.BASE, 'portal')
KEY = os.path.join(PORTAL_DIR, 'portal.key')
CRT = os.path.join(PORTAL_DIR, 'portal.crt')
AUTHCHECK = '/usr/local/opnsense/scripts/OPNsense/Layer7Security/authcheck.php'
REDIRECT_PORT = 8081
MAX_BODY = 4096
THROTTLE_FAILS, THROTTLE_WINDOW, THROTTLE_LOCK = 5, 600, 300
SECRET = secrets.token_bytes(32)
fails = {}          # ip -> [timestamps of recent failures]
locked = {}         # ip -> unlock time
lock = threading.Lock()

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%(title)s</title><style>
:root{color-scheme:light dark}
body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#f3f4f6;color:#1f2933;display:flex;min-height:100vh;align-items:center;justify-content:center}
@media (prefers-color-scheme:dark){body{background:#14181d;color:#e4e7eb}.card{background:#1d232a!important;border-color:#2c353f!important}input{background:#14181d!important;color:#e4e7eb!important;border-color:#3a4552!important}}
.card{background:#fff;border:1px solid #d9dde2;border-radius:14px;padding:28px 26px;width:min(92vw,380px);box-shadow:0 6px 24px rgba(0,0,0,.08)}
h1{font-size:21px;margin:0 0 6px}p{margin:0 0 16px;color:#6b7785;font-size:14px;line-height:1.45}
label{display:block;font-size:13px;margin:12px 0 4px}input[type=text],input[type=password]{width:100%%;box-sizing:border-box;padding:10px 11px;border:1px solid #c5ccd3;border-radius:8px;font-size:15px}
button{margin-top:18px;width:100%%;padding:11px;border:0;border-radius:8px;background:#d94f00;color:#fff;font-size:15px;font-weight:600;cursor:pointer}
.err{background:#fde8e8;color:#9b1c1c;border-radius:8px;padding:9px 11px;font-size:13px;margin-bottom:6px}
.ok{background:#e3f6ea;color:#14633a;border-radius:8px;padding:9px 11px;font-size:13px;margin-bottom:10px}
.small{font-size:12px;margin-top:16px;color:#8a95a1}a{color:#d94f00}
</style></head><body><div class="card">%(body)s</div></body></html>"""


def render(title, body):
    return (PAGE % {'title': html.escape(title), 'body': body}).encode()


def esc(text):
    return html.escape(str(text), quote=True)


def token_for(ip):
    ts = str(int(time.time()) // 600)
    return hmac.new(SECRET, (ip + ts).encode(), hashlib.sha256).hexdigest()[:32]


def token_ok(ip, tok):
    now = int(time.time()) // 600
    for ts in (now, now - 1):
        good = hmac.new(SECRET, (ip + str(ts)).encode(), hashlib.sha256).hexdigest()[:32]
        if hmac.compare_digest(good, tok or ''):
            return True
    return False


def safe_next(url):
    """only plain http(s) addresses to a host name are used as the "go on" target"""
    try:
        p = urlsplit(url)
    except ValueError:
        return ''
    if p.scheme in ('http', 'https') and p.hostname and re.fullmatch(r'[A-Za-z0-9.-]{1,253}', p.hostname) and len(url) < 800:
        return url
    return ''


def firewall_address_for(client):
    """the firewall address in the network of this client"""
    cfg = auth.config()
    try:
        ip = ipaddress.ip_address(client)
    except ValueError:
        return ''
    for n in cfg.get('networks', []):
        try:
            if ip in ipaddress.ip_network(n['net'], strict=False):
                return n['ip']
        except (ValueError, KeyError):
            continue
    nets = cfg.get('networks', [])
    return nets[0]['ip'] if nets else ''


def mac_of(ip):
    try:
        res = subprocess.run(['/usr/sbin/arp', '-n', ip], capture_output=True, text=True, timeout=3)
        m = re.search(r'at ([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})', res.stdout)
        return m.group(1) if m else ''
    except (OSError, subprocess.SubprocessError):
        return ''


def check_password(user, password):
    """-> (ok, message); the password goes to the PHP helper on stdin, never on a command line"""
    cfg = auth.config()
    req = json.dumps({'server': cfg.get('server', 'Local Database'), 'user': user, 'pass': password,
                      'groups': cfg.get('groups', [])})
    try:
        res = subprocess.run(['/usr/local/bin/php', AUTHCHECK], input=req, capture_output=True, text=True, timeout=20)
        data = json.loads(res.stdout.strip().splitlines()[-1])
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return False, 'The sign-in service is not available. Please try again later.'
    if data.get('ok'):
        return True, ''
    if data.get('error') == 'group':
        return False, 'Your account is not allowed to use the internet here.'
    if data.get('error') == 'server':
        return False, 'The sign-in service is not set up correctly. Please tell your administrator.'
    return False, 'Wrong user name or password.'


def throttled(ip):
    with lock:
        t = time.time()
        if locked.get(ip, 0) > t:
            return int(locked[ip] - t)
        return 0


def record_fail(ip):
    with lock:
        t = time.time()
        lst = [x for x in fails.get(ip, []) if t - x < THROTTLE_WINDOW] + [t]
        fails[ip] = lst
        if len(lst) >= THROTTLE_FAILS:
            locked[ip] = t + THROTTLE_LOCK
            fails[ip] = []
            return True
    return False


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'l7portal'
    sys_version = ''
    timeout = 15

    def log_message(self, fmt, *args):      # keep the log quiet
        pass

    def send_page(self, code, body, extra=None):
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
        self.send_header('Referrer-Policy', 'no-referrer')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def client(self):
        return self.client_address[0]

    def login_form(self, nxt='', error='', info=''):
        cfg = auth.config()
        ip = self.client()
        body = '<h1>%s</h1><p>%s</p>' % (esc(cfg.get('title', 'Sign in')), esc(cfg.get('message', '')))
        if error:
            body += '<div class="err">%s</div>' % esc(error)
        if info:
            body += '<div class="ok">%s</div>' % esc(info)
        body += ('<form method="post" action="/login" autocomplete="on"><input type="hidden" name="t" value="%s">'
                 '<input type="hidden" name="next" value="%s"><label for="u">User name</label>'
                 '<input id="u" name="user" type="text" autocomplete="username" autocapitalize="none" required autofocus>'
                 '<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>'
                 '<button type="submit">Sign in</button></form>'
                 '<div class="small">Your device address (%s) is signed in for the next %s hours.</div>') % (
                     token_for(ip), esc(nxt), esc(ip), esc(cfg.get('sessionHours', 8)))
        return render(cfg.get('title', 'Sign in'), body)

    def signed_in_page(self, sess, nxt=''):
        t = time.strftime('%Y-%m-%d %H:%M', time.localtime(sess['expires']))
        body = ('<h1>You are signed in</h1><div class="ok">Signed in as <strong>%s</strong>. This lasts until %s.</div>'
                % (esc(sess['user']), esc(t)))
        if safe_next(nxt):
            body += '<p><a href="%s">Continue to the website you asked for</a></p>' % esc(nxt)
        body += ('<form method="post" action="/logout"><input type="hidden" name="t" value="%s">'
                 '<button type="submit" style="background:#6b7785">Sign out</button></form>' % token_for(self.client()))
        return render('Signed in', body)

    def read_form(self):
        try:
            n = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY:
            return {}
        raw = self.rfile.read(n).decode('utf-8', 'replace')
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlsplit(self.path).path
        q = parse_qs(urlsplit(self.path).query)
        nxt = safe_next((q.get('next') or [''])[0])
        sess = auth.session_of(self.client())
        if path in ('/', '/login', '/status'):
            if sess:
                self.send_page(200, self.signed_in_page(sess, nxt))
            else:
                self.send_page(200, self.login_form(nxt))
        elif path == '/health':
            self.send_page(200, b'ok')
        else:
            self.send_response(302)
            self.send_header('Location', '/login')
            self.send_header('Content-Length', '0')
            self.end_headers()

    def do_POST(self):
        ip = self.client()
        path = urlsplit(self.path).path
        form = self.read_form()
        if path == '/logout':
            if token_ok(ip, form.get('t', '')):
                auth.logout(ip, 'logout', 'signed out by the user')
            self.send_page(200, self.login_form(info='You are signed out.'))
            return
        if path != '/login':
            self.send_page(404, render('Not found', '<h1>Not found</h1>'))
            return
        nxt = safe_next(form.get('next', ''))
        if not token_ok(ip, form.get('t', '')):
            self.send_page(200, self.login_form(nxt, 'The page was open too long. Please try again.'))
            return
        wait = throttled(ip)
        if wait:
            self.send_page(429, self.login_form(nxt, 'Too many wrong attempts. Try again in %d minutes.' % (wait // 60 + 1)))
            return
        user = form.get('user', '').strip()
        password = form.get('password', '')
        if not user or not password or len(user) > 64 or len(password) > 256:
            self.send_page(200, self.login_form(nxt, 'Enter your user name and password.'))
            return
        ok, msg = check_password(user, password)
        con = auth.connect()
        if not ok:
            with con:
                auth.log_event(con, 'fail', user, ip, msg)
                if record_fail(ip):
                    auth.log_event(con, 'lockout', user, ip, 'too many wrong attempts')
            con.close()
            self.send_page(200, self.login_form(nxt, msg))
            return
        con.close()
        sess = auth.login(ip, user, mac_of(ip))
        self.send_page(200, self.signed_in_page(sess, nxt))


class Redirect(http.server.BaseHTTPRequestHandler):
    """plain HTTP from devices that are not signed in: send them to the login page"""
    server_version = 'l7portal'
    sys_version = ''
    timeout = 10

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        cfg = auth.config()
        fw = firewall_address_for(self.client_address[0])
        host = self.headers.get('Host', '')
        nxt = ''
        if re.fullmatch(r'[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?', host or '') and self.path.startswith('/') and len(self.path) < 500:
            nxt = 'http://' + host + self.path
        target = 'https://%s:%d/login' % (fw, int(cfg.get('port', 8444)))
        if nxt:
            target += '?next=' + quote(nxt, safe='')
        self.send_response(302)
        self.send_header('Location', target)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', '0')
        self.send_header('Connection', 'close')
        self.end_headers()

    do_HEAD = do_GET
    do_POST = do_GET


class Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


class TLSServer(Threaded):
    """the TLS handshake runs in the worker thread, so a stalled client cannot block the accept loop"""
    context = None

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(10)
        return sock, addr

    def finish_request(self, request, client_address):
        try:
            tls = self.context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        self.RequestHandlerClass(tls, client_address, self)


def ensure_certificate(addresses):
    """a self-signed certificate for the portal address (created once)"""
    os.makedirs(PORTAL_DIR, mode=0o700, exist_ok=True)
    if os.path.exists(KEY) and os.path.exists(CRT):
        return
    san = ','.join(['IP:' + a for a in addresses] + ['DNS:firewall.local'])
    subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
                    '-subj', '/CN=Layer 7 Security sign-in', '-addext', 'subjectAltName=' + san,
                    '-keyout', KEY, '-out', CRT], capture_output=True, timeout=60, check=True)
    os.chmod(KEY, 0o600)


def manager():
    while True:
        try:
            auth.expire()
            auth.sync()
        except Exception as exc:       # keep going: a failed round is retried
            sys.stderr.write('portal manager: %r\n' % (exc,))
        time.sleep(15)


def main():
    cfg = auth.config()
    nets = cfg.get('networks', [])
    addresses = [n['ip'] for n in nets if 'ip' in n]
    if not addresses:
        sys.stderr.write('no portal interface configured\n')
        return 1
    ensure_certificate(addresses)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CRT, KEY)
    servers = []
    for a in addresses:
        s = TLSServer((a, int(cfg.get('port', 8444))), Handler)
        s.context = ctx
        servers.append(s)
    servers.append(Threaded(('127.0.0.1', REDIRECT_PORT), Redirect))
    for s in servers:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    auth.sync()
    manager()
    return 0


if __name__ == '__main__':
    sys.exit(main())
