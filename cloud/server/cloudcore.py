#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Business logic shared by the feed server (check-in, trial) and the dashboard
# (license generator, firewall list, feed health).

import json
import os
import re
import sqlite3
import time

import licenselib
import store

LICENSE_DIR = os.path.join(store.ROOT, 'license')
PRIVATE_PEM = os.path.join(LICENSE_DIR, 'signing.pem')
PUBLIC_PEM = os.path.join(LICENSE_DIR, 'public.pem')
FEEDS = os.environ.get('L7_CLOUD_FEEDS', os.path.join(store.ROOT, 'feeds'))
BUILD_STATUS = os.path.join(store.ROOT, 'build_status.json')
BUILD_LOG = os.path.join(store.ROOT, 'build.log')


def ensure_keys():
    """create the vendor signing key on the first start; the public key file is what the plugin embeds"""
    pub = licenselib.generate_keypair(PRIVATE_PEM)
    if not os.path.exists(PUBLIC_PEM) or open(PUBLIC_PEM).read() != pub:
        with open(PUBLIC_PEM, 'w', newline='') as f:
            f.write(pub)
    return pub


def public_pem():
    with open(PUBLIC_PEM) as f:
        return f.read()


def clean(text, limit=80):
    return re.sub(r'[\x00-\x1f\x7f<>"\']', '', str(text or ''))[:limit].strip()


def store_license(con, info, customer, note, install_id, source):
    with con:
        con.execute('INSERT INTO licenses(key_id,key,type,customer,note,issued,expires,bound_install,created,source)'
                    ' VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (info['key_id'], info['key'], info['type'], clean(customer), clean(note, 200), info['issued'],
                     info['expires'], install_id.upper() if install_id else '', int(time.time()), source))


def issue_license(con, type_name, customer, note='', install_id='', issued_ts=None, source='dashboard'):
    if type_name not in licenselib.TYPE_IDS:
        raise ValueError('Choose trial, year or lifetime.')
    install_id = (install_id or '').strip().upper()
    if install_id and not licenselib.valid_install_id(install_id):
        raise ValueError('The installation id looks like 1234-ABCD-5678-EF01.')
    info = licenselib.issue(type_name, PRIVATE_PEM, install_id, issued_ts)
    store_license(con, info, customer, note, install_id, source)
    return info


def license_row(con, key_id):
    return con.execute('SELECT * FROM licenses WHERE key_id=?', (key_id,)).fetchone()


def row_state(row, now=None):
    """active, expired or revoked"""
    now = now or int(time.time())
    if row['revoked']:
        return 'revoked'
    if row['expires'] is not None and row['expires'] <= now:
        return 'expired'
    return 'active'


def checkin(con, ip, data):
    """a firewall reports in: record it, answer with the state of its license"""
    install_id = clean(data.get('install_id', ''), 20).upper()
    if not licenselib.valid_install_id(install_id):
        return {'ok': False, 'error': 'bad installation id'}
    key = str(data.get('key', ''))[:400]
    state, message, key_id, update = 'none', 'No license key on this firewall.', '', None
    if key:
        info = licenselib.parse(key, public_pem())
        if not info['ok']:
            state, message = 'invalid', info['error']
        else:
            key_id = info['key_id']
            row = license_row(con, key_id)
            if row is None:
                # signed by us but not in the database (restored from a backup, or issued offline): accept and record
                store_license(con, info, 'unknown (not issued here)', 'seen at check-in', '', 'offline')
                row = license_row(con, key_id)
            state = row_state(row)
            message = {'active': 'License is active.', 'expired': 'License has expired.',
                       'revoked': 'License was withdrawn by the vendor.'}[state]
            if row['replacement_key'] and row['replacement_key'] != key:
                update = row['replacement_key']
    version = clean(data.get('version', ''), 20)
    host = clean(data.get('hostname', ''), 64)
    os_name = clean(data.get('os', ''), 40)
    info_blob = {k: data[k] for k in ('engine', 'features', 'feeds') if k in data and len(json.dumps(data[k])) < 2000}
    store.note_client(con, install_id, ip, host, version, os_name, key_id, state, info_blob)
    out = {'ok': True, 'license': {'state': state, 'message': message}, 'server_time': int(time.time())}
    if update:
        out['update_key'] = update
    return out


def trial(con, ip, data):
    """a 30 day trial key tied to the firewall, once per installation id"""
    if store.get_setting(con, 'trials_enabled', '1') != '1':
        return {'ok': False, 'error': 'Trial keys are switched off on this server. Ask your vendor for a key.'}
    install_id = clean(data.get('install_id', ''), 20).upper()
    if not licenselib.valid_install_id(install_id):
        return {'ok': False, 'error': 'bad installation id'}
    row = con.execute('SELECT key_id FROM trials WHERE install_id=?', (install_id,)).fetchone()
    if row:
        lic = license_row(con, row['key_id'])
        if lic is not None and row_state(lic) == 'active':
            return {'ok': True, 'key': lic['key'], 'again': True}
        return {'ok': False, 'error': 'A trial was already used on this firewall. Ask your vendor for a license key.'}
    host = clean(data.get('hostname', ''), 64) or 'Trial'
    info = issue_license(con, 'trial', host, 'self-service trial from ' + ip, install_id, source='trial')
    with con:
        con.execute('INSERT INTO trials(install_id,key_id,ts) VALUES(?,?,?)', (install_id, info['key_id'], int(time.time())))
    return {'ok': True, 'key': info['key'], 'again': False}


# ---- dashboard data
def read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def feed_files():
    """every published file with size and age"""
    out = []
    for root, _dirs, files in os.walk(FEEDS):
        for name in sorted(files):
            if name.endswith('.tmp'):
                continue
            p = os.path.join(root, name)
            rel = os.path.relpath(p, FEEDS).replace(os.sep, '/')
            try:
                st = os.stat(p)
            except OSError:
                continue
            lines = 0
            if name.endswith('.txt'):
                try:
                    with open(p, 'rb') as f:
                        lines = sum(1 for ln in f if ln.strip() and not ln.startswith(b'#'))
                except OSError:
                    pass
            out.append({'path': rel, 'size': st.st_size, 'mtime': int(st.st_mtime), 'entries': lines})
    return out


def overview(con):
    now = int(time.time())
    day = now - 86400
    status = read_json(BUILD_STATUS, {})
    last = (status.get('history') or [{}])[0] if status.get('history') else {}
    lic = {'active': 0, 'expired': 0, 'revoked': 0, 'expiring': 0}
    for row in con.execute('SELECT * FROM licenses'):
        st = row_state(row, now)
        lic[st] += 1
        if st == 'active' and row['expires'] is not None and row['expires'] - now < 14 * 86400:
            lic['expiring'] += 1
    clients = con.execute('SELECT COUNT(*) FROM clients').fetchone()[0]
    seen24 = con.execute('SELECT COUNT(*) FROM clients WHERE last_seen >= ?', (day,)).fetchone()[0]
    req24 = con.execute('SELECT COUNT(*), COALESCE(SUM(bytes),0) FROM requests WHERE ts >= ?', (day,)).fetchone()
    errors24 = con.execute('SELECT COUNT(*) FROM requests WHERE ts >= ? AND status >= 400', (day,)).fetchone()[0]
    files = feed_files()
    st = os.statvfs(store.ROOT) if os.path.isdir(store.ROOT) else None
    disk = {'free': st.f_bavail * st.f_frsize, 'total': st.f_blocks * st.f_frsize} if st else {}
    return {'now': now, 'build': last, 'running': build_running(), 'licenses': lic,
            'firewalls': {'total': clients, 'seen24h': seen24}, 'requests24h': {'count': req24[0], 'bytes': req24[1], 'errors': errors24},
            'files': len(files), 'feedBytes': sum(f['size'] for f in files), 'disk': disk,
            'trials': store.get_setting(con, 'trials_enabled', '1') == '1'}


def build_running():
    p = os.path.join(store.ROOT, 'build.lock')
    try:
        with open(p) as f:
            pid = int(f.read().strip() or 0)
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def clients(con):
    now = int(time.time())
    out = []
    for r in con.execute('SELECT * FROM clients ORDER BY last_seen DESC'):
        d = dict(r)
        d['info'] = read_json_text(d.get('info'))
        d['online'] = now - d['last_seen'] < 3 * 3600 + 600
        lic = license_row(con, d['key_id']) if d['key_id'] else None
        d['license'] = None if lic is None else {'type': lic['type'], 'expires': lic['expires'], 'state': row_state(lic, now),
                                                 'customer': lic['customer']}
        out.append(d)
    return out


def read_json_text(text):
    try:
        return json.loads(text or '{}')
    except ValueError:
        return {}


def licenses(con):
    now = int(time.time())
    out = []
    for r in con.execute('SELECT * FROM licenses ORDER BY created DESC'):
        d = dict(r)
        d['state'] = row_state(r, now)
        d['days_left'] = None if r['expires'] is None else (r['expires'] - now) // 86400
        used = con.execute('SELECT install_id, hostname, last_seen FROM clients WHERE key_id=? ORDER BY last_seen DESC LIMIT 3',
                           (r['key_id'],)).fetchall()
        d['used_by'] = [dict(u) for u in used]
        out.append(d)
    return out


def set_revoked(con, key_id, revoked):
    with con:
        n = con.execute('UPDATE licenses SET revoked=?, revoked_ts=? WHERE key_id=?',
                        (1 if revoked else 0, int(time.time()) if revoked else None, key_id)).rowcount
    return n > 0


def replace_license(con, key_id, type_name, install_id=''):
    """issue a new key for the same customer; the firewall picks it up at its next check-in"""
    old = license_row(con, key_id)
    if old is None:
        raise ValueError('Unknown license.')
    new = issue_license(con, type_name, old['customer'], 'replaces ' + key_id, install_id or old['bound_install'], source='renewal')
    with con:
        con.execute('UPDATE licenses SET replacement_key=? WHERE key_id=?', (new['key'], key_id))
    return new
