#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# TLS inspection plumbing: the inspection CA, the Squid configuration and the
# status of the proxy / ICAP processes.
#
#   inspection.py ca-init [--force]   create the CA (once) or replace it
#   inspection.py ca-info             JSON about the CA
#   inspection.py ca-pem              print the CA certificate (PEM)
#   inspection.py write-config        build squid.conf from inspection.json
#   inspection.py status              JSON: processes and counters
#   inspection.py test PATH           scan a text file (deleted afterwards), JSON of masked detections
#
# The CA carries an X.509 name-constraints extension limited to the catalog's
# AI service domains, so even a stolen CA key cannot impersonate other sites
# to clients that enforce name constraints.

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dlp_rules  # noqa: E402

BASE = os.environ.get('L7_BASE', '/var/db/layer7security')
CONF_DIR = os.environ.get('L7_CONF_DIR', '/usr/local/etc/layer7security')
CA_DIR = os.path.join(BASE, 'ca')
CA_KEY = os.path.join(CA_DIR, 'ca.key')
CA_CRT = os.path.join(CA_DIR, 'ca.crt')
SQUID_HOME = os.environ.get('L7_SQUID_HOME', '/var/db/l7squid')   # squid-owned: the certificate helper runs as that user
SSL_DB = os.path.join(SQUID_HOME, 'ssl_db')
SETTINGS = os.path.join(CONF_DIR, 'inspection.json')
SQUID_CONF = os.path.join(CONF_DIR, 'squid.conf')
CATALOG = os.environ.get('L7_AI_CATALOG', '/usr/local/share/layer7security/ai_services.json')
OPENSSL = shutil.which('openssl') or '/usr/bin/openssl'
CERTGEN = '/usr/local/libexec/squid/security_file_certgen'
HTTP_PORT, HTTPS_PORT, ICAP_PORT = 3128, 3129, 1344
DOMAIN = re.compile(r'^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$')
STATS = '/var/run/layer7security/icap_stats.json'


def av_domains():
    """HTTPS sites chosen for download protection"""
    try:
        with open(SETTINGS) as f:
            doms = (json.load(f).get('av') or {}).get('https_domains') or []
    except (OSError, ValueError):
        return []
    return sorted({d.lower().lstrip('.') for d in doms if DOMAIN.match(d.lower().lstrip('.'))})


def catalog_domains():
    try:
        with open(CATALOG) as f:
            doms = {d.lower() for s in json.load(f) for d in s.get('domains', []) if DOMAIN.match(d.lower())}
    except (OSError, ValueError):
        doms = set()
    return sorted(doms | set(av_domains()))      # sites the CA may sign for: AI services and chosen download sites


def ca_check():
    """configured inspection sites the existing CA is not allowed to sign for"""
    if not os.path.exists(CA_CRT):
        return {'uncovered': []}
    allowed = ca_info().get('constraints', [])
    wanted = set(av_domains())
    try:
        with open(SETTINGS) as f:
            for r in json.load(f).get('rules', []):
                wanted |= {d.lower() for d in r.get('domains', []) if DOMAIN.match(d.lower())}
    except (OSError, ValueError):
        pass
    bad = sorted(d for d in wanted if not any(d == a or d.endswith('.' + a) for a in allowed))
    return {'uncovered': bad}


def run(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, timeout=120, **kw)


def chown_squid(path, mode=None, recursive=False):
    try:
        import grp
        import pwd
        uid, gid = pwd.getpwnam('squid').pw_uid, grp.getgrnam('squid').gr_gid
    except (ImportError, KeyError):
        return
    paths = [path]
    if recursive:
        for root, dirs, files in os.walk(path):
            paths += [os.path.join(root, n) for n in dirs + files]
    for p in paths:
        try:
            os.chown(p, uid, gid)
        except OSError:
            pass
    if mode is not None:
        os.chmod(path, mode)


def ca_init(force=False):
    if os.path.exists(CA_CRT) and os.path.exists(CA_KEY) and not force:
        return {'created': False}
    domains = catalog_domains()
    if not domains:
        return {'created': False, 'error': 'AI service catalog is empty'}
    os.makedirs(CA_DIR, mode=0o750, exist_ok=True)
    nc = '\n'.join('permitted;DNS.%d = %s' % (i, d) for i, d in enumerate(domains))
    conf = ('[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n'
            '[dn]\nCN = Layer 7 Security AI inspection CA (%s)\nO = os-layer7security\n'
            '[ext]\nbasicConstraints = critical,CA:TRUE,pathlen:0\nkeyUsage = critical,keyCertSign,cRLSign\n'
            'subjectKeyIdentifier = hash\nnameConstraints = critical,@nc\n[nc]\n%s\n') % (socket.gethostname()[:40], nc)
    with tempfile.NamedTemporaryFile('w', suffix='.cnf', delete=False) as f:
        f.write(conf)
        cnf = f.name
    try:
        key, crt = CA_KEY + '.new', CA_CRT + '.new'
        res = run([OPENSSL, 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '730', '-sha256',
                   '-keyout', key, '-out', crt, '-config', cnf])
        if res.returncode != 0:
            return {'created': False, 'error': res.stderr[-300:]}
    finally:
        os.unlink(cnf)
    os.chmod(key, 0o640)
    os.chmod(crt, 0o644)
    chown_squid(key, 0o640)          # root:squid so the proxy can read it
    os.replace(key, CA_KEY)
    os.replace(crt, CA_CRT)
    if os.path.isdir(SSL_DB):          # certificates minted by the old CA are useless now
        shutil.rmtree(SSL_DB, ignore_errors=True)
    return {'created': True, 'domains': len(domains)}


def ca_info():
    if not os.path.exists(CA_CRT):
        return {'exists': False}
    out = {'exists': True}
    for key, args in (('subject', ['-subject']), ('notBefore', ['-startdate']), ('notAfter', ['-enddate']),
                      ('fingerprint', ['-fingerprint', '-sha256'])):
        res = run([OPENSSL, 'x509', '-in', CA_CRT, '-noout'] + args)
        text = res.stdout.strip()
        out[key] = text.split('=', 1)[1].strip() if '=' in text else text
    res = run([OPENSSL, 'x509', '-in', CA_CRT, '-noout', '-ext', 'nameConstraints'])
    out['constraints'] = re.findall(r'DNS:([A-Za-z0-9.-]+)', res.stdout)
    return out


def ca_pem():
    try:
        with open(CA_CRT) as f:
            return f.read()
    except OSError:
        return ''


def acl_name(prefix, i):
    return '%s%d' % (prefix, i)


def build_squid(cfg):
    """squid.conf text for the AI inspection rules and (optionally) web antivirus"""
    rules = [r for r in cfg.get('rules', []) if r.get('domains')]
    av = cfg.get('av', {}) if cfg.get('av', {}).get('enabled') else {}
    lines = ['# generated by os-layer7security, do not edit',
             'pid_filename none',            # supervised by daemon(8), which holds the pid file
             'cache_effective_user squid', 'cache_effective_group proxy',   # /dev/pf is root:proxy (NAT lookup)
             'visible_hostname l7security', 'httpd_suppress_version_string on',
             'via off', 'forwarded_for delete', 'cache deny all', 'cache_mem 8 MB',
             'access_log none', 'cache_store_log none', 'cache_log /var/log/l7squid/cache.log',
             'coredump_dir /var/db/l7squid', 'shutdown_lifetime 1 seconds',
             'client_persistent_connections on', 'server_persistent_connections on',
             # Squid insists on one ordinary port to build its internal URLs; it serves nobody (see http_access)
             'http_port 127.0.0.1:3127 name=l7fwd', 'acl l7_fwdport myportname l7fwd']
    if rules:
        lines += ['https_port 127.0.0.1:%d intercept ssl-bump generate-host-certificates=on '
                  'dynamic_cert_mem_cache_size=4MB cert=%s key=%s options=NO_SSLv3,NO_TLSv1,NO_TLSv1_1' %
                  (HTTPS_PORT, CA_CRT, CA_KEY),
                  'sslcrtd_program %s -s %s -M 4MB' % (CERTGEN, SSL_DB), 'sslcrtd_children 5',
                  'tls_outgoing_options cafile=/usr/local/etc/ssl/cert.pem min-version=1.2',
                  'acl l7_step1 at_step SslBump1']
    if av.get('http', True) and av:
        lines.append('http_port 127.0.0.1:%d intercept' % HTTP_PORT)
    if av and av.get('https_domains') and not rules:
        lines += ['https_port 127.0.0.1:%d intercept ssl-bump generate-host-certificates=on '
                  'dynamic_cert_mem_cache_size=4MB cert=%s key=%s options=NO_SSLv3,NO_TLSv1,NO_TLSv1_1' %
                  (HTTPS_PORT, CA_CRT, CA_KEY),
                  'sslcrtd_program %s -s %s -M 4MB' % (CERTGEN, SSL_DB), 'sslcrtd_children 5',
                  'tls_outgoing_options cafile=/usr/local/etc/ssl/cert.pem min-version=1.2',
                  'acl l7_step1 at_step SslBump1']
    # one ACL pair per inspection rule
    bump, dlp_allow = [], []
    for i, r in enumerate(rules):
        doms = ' '.join('.' + d for d in r['domains'] if DOMAIN.match(d))
        lines.append('acl %s ssl::server_name %s' % (acl_name('l7_sni', i), doms))
        lines.append('acl %s dstdomain %s' % (acl_name('l7_host', i), doms))
        srcs = [s for s in r.get('sources', []) if re.match(r'^[0-9a-fA-F:./]+$', s)]
        names = [acl_name('l7_sni', i)]
        hnames = [acl_name('l7_host', i)]
        if srcs:
            lines.append('acl %s src %s' % (acl_name('l7_src', i), ' '.join(srcs)))
            names.append(acl_name('l7_src', i))
            hnames.append(acl_name('l7_src', i))
        bump.append(' '.join(names))
        dlp_allow.append(' '.join(hnames))
    av_domains = []
    if av and av.get('https_domains'):
        av_domains = [d for d in av['https_domains'] if DOMAIN.match(d)]
        if av_domains:
            lines.append('acl l7_av_sni ssl::server_name ' + ' '.join('.' + d for d in av_domains))
    if rules or av_domains:
        lines.append('ssl_bump peek l7_step1')
        for b in bump:
            lines.append('ssl_bump bump ' + b)
        if av_domains:
            lines.append('ssl_bump bump l7_av_sni')
        lines.append('ssl_bump splice all')
    lines += ['http_access deny l7_fwdport', 'http_access allow all', 'icap_enable on', 'icap_send_client_ip on', 'icap_io_timeout 60 seconds',
              'icap_preview_enable off']
    if rules:
        bypass = 'on' if cfg.get('failMode') == 'open' else 'off'
        lines.append('icap_service l7_dlp reqmod_precache icap://127.0.0.1:%d/dlp bypass=%s routing=off' % (ICAP_PORT, bypass))
        for a in dlp_allow:
            lines.append('adaptation_access l7_dlp allow ' + a)
        lines.append('adaptation_access l7_dlp deny all')
    if av:
        bypass = 'on' if av.get('failMode') == 'open' else 'off'
        lines.append('icap_service l7_av respmod_precache icap://127.0.0.1:%d/av bypass=%s routing=off' % (ICAP_PORT, bypass))
        ai_doms = sorted({d for r in rules for d in r['domains'] if DOMAIN.match(d)})
        skip = sorted(set(ai_doms) | {d.lstrip('.') for d in av.get('skip', []) if DOMAIN.match(d.lstrip('.'))})
        if skip:              # streaming AI responses are never buffered for scanning; neither are trusted sites
            lines.append('acl l7_av_skip dstdomain ' + ' '.join('.' + d for d in skip))
            lines.append('adaptation_access l7_av deny l7_av_skip')
        lines.append('adaptation_access l7_av allow all')
    return '\n'.join(lines) + '\n'


def write_config():
    try:
        with open(SETTINGS) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        cfg = {}
    text = build_squid(cfg)
    os.makedirs(CONF_DIR, exist_ok=True)
    with open(SQUID_CONF + '.tmp', 'w') as f:
        f.write(text)
    os.replace(SQUID_CONF + '.tmp', SQUID_CONF)
    for d in ('/var/log/l7squid',):
        os.makedirs(d, exist_ok=True)
        chown_squid(d, 0o750)
    os.makedirs(SQUID_HOME, exist_ok=True)
    chown_squid(SQUID_HOME, 0o700)
    if (cfg.get('rules') or cfg.get('av', {}).get('https_domains')) and not os.path.isdir(SSL_DB) and os.path.exists(CERTGEN):
        res = run([CERTGEN, '-c', '-s', SSL_DB, '-M', '4MB'])
        if res.returncode != 0 and not os.path.isdir(SSL_DB):
            return {'written': True, 'warning': 'ssl_db: ' + res.stderr[-200:]}
    if os.path.isdir(SSL_DB):
        chown_squid(SSL_DB, 0o700, recursive=True)
    return {'written': True, 'rules': len(cfg.get('rules', []))}


def alive(pidfile):
    try:
        with open(pidfile) as f:
            os.kill(int(f.read().strip()), 0)
        return True
    except (OSError, ValueError):
        return False


def status():
    out = {'squid': alive('/var/run/l7squid.pid'), 'icap': alive('/var/run/l7icap.pid'),
           'ca': os.path.exists(CA_CRT), 'icapStats': {}}
    try:
        with open(STATS) as f:
            out['icapStats'] = json.load(f)
    except (OSError, ValueError):
        pass
    return out


def test_file(path):
    """scan a text file for the GUI test box; the file is removed, nothing is logged"""
    if not re.match(r'^/tmp/l7test\.[A-Za-z0-9]{6,32}$', path) or not os.path.isfile(path):
        return {'error': 'bad path'}
    try:
        with open(path, 'rb') as f:
            raw = f.read(1024 * 1024)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    try:
        with open(os.path.join(CONF_DIR, 'inspection.json')) as f:
            settings = json.load(f)
    except (OSError, ValueError):
        settings = {}
    actions = dict({'card': 'block', 'id': 'block', 'api_key': 'block', 'code': 'monitor'}, **settings.get('categories', {}))
    text = raw.decode('utf-8', 'replace')
    res = []
    for det in dlp_rules.scan(text, [c for c, a in actions.items() if a != 'off'], int(settings.get('codeMinLines', 12))):
        res.append({'category': det.category, 'rule': det.rule.split(':')[0], 'action': actions.get(det.category),
                    'masked': dlp_rules.snippet(text, det) or det.rule})
    return {'detections': res, 'masked': dlp_rules.mask_text(text)[:400]}


def main():
    a = sys.argv[1:]
    cmd = a[0] if a else 'status'
    if cmd == 'ca-init':
        out = ca_init('--force' in a)
    elif cmd == 'ca-info':
        out = ca_info()
    elif cmd == 'ca-check':
        out = ca_check()
    elif cmd == 'ca-pem':
        sys.stdout.write(ca_pem())
        return
    elif cmd == 'write-config':
        out = write_config()
    elif cmd == 'test':
        out = test_file(a[1] if len(a) > 1 else '')
    else:
        out = status()
    print(json.dumps(out))


if __name__ == '__main__':
    main()
