#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Talks to the vendor's cloud server about the license.
#
#   license_cloud.py checkin   report to the server (installation id, version, key); apply what it answers
#   license_cloud.py trial     ask the server for a 30 day trial key and activate it
#   license_cloud.py status    what the last contact looked like (JSON)
#
# The server address is the cloud server address of the plugin (the "/feeds" part is dropped).
# Prints JSON.

import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cloudlib  # noqa: E402

LICENSE_PHP = '/usr/local/opnsense/scripts/OPNsense/Layer7Security/license.php'
STATE = os.path.join(cloudlib.BASE, 'license_cloud.json')
LICENSE_FILE = os.path.join(cloudlib.BASE, 'license.json')
VERSION_FILE = '/usr/local/opnsense/mvc/app/models/OPNsense/Layer7Security/Layer7Security.xml'
PKG_NAME = 'os-layer7security'


def install_id():
    try:
        uuid = subprocess.run(['/sbin/sysctl', '-n', 'kern.hostuuid'], capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        uuid = ''
    if not uuid:
        try:
            with open('/etc/hostid') as f:
                uuid = f.read().strip()
        except OSError:
            pass
    h = hashlib.sha256(('L7INST1|' + uuid).encode()).hexdigest()[:16].upper()
    return '-'.join(h[i:i + 4] for i in range(0, 16, 4))


def server_root(cfg):
    base = cloudlib.base_url(cfg)
    return re.sub(r'/feeds$', '', base) if base else ''


def plugin_version():
    try:
        out = subprocess.run(['/usr/sbin/pkg', 'query', '%v', PKG_NAME], capture_output=True, text=True, timeout=10).stdout.strip()
        return out.split('\n')[0][:20]
    except (OSError, subprocess.SubprocessError):
        return ''


def read_state():
    try:
        with open(STATE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def write_state(d):
    cloudlib.write_atomic(STATE, json.dumps(d))


def php(*args):
    try:
        out = subprocess.run([LICENSE_PHP] + list(args), capture_output=True, text=True, timeout=120).stdout.strip()
        return json.loads(out.splitlines()[-1]) if out else {}
    except (OSError, ValueError, subprocess.SubprocessError, IndexError):
        return {}


def current_key():
    try:
        with open(LICENSE_FILE) as f:
            return str(json.load(f).get('key', ''))
    except (OSError, ValueError):
        return ''


def post(url, data, timeout=20):
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json', 'User-Agent': 'os-layer7security'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read(65536).decode('utf-8', 'replace'))
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read(65536).decode('utf-8', 'replace'))
        except ValueError:
            return {'ok': False, 'error': 'server answered HTTP %d' % exc.code}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {'ok': False, 'error': 'cannot reach the server (%s)' % str(getattr(exc, 'reason', exc))[:80]}


def last_feed_update():
    st = cloudlib.load_state()
    ts = 0
    for part in ('domains', 'ips', 'hashes'):
        for v in (st.get(part) or {}).values():
            if isinstance(v, dict):
                ts = max(ts, int(v.get('ts', 0) or 0))
    sig = st.get('signatures')
    if isinstance(sig, dict):
        ts = max(ts, int(sig.get('ts', 0) or 0))
    return ts


def checkin():
    cfg = cloudlib.settings()
    root = server_root(cfg)
    st = read_state()
    if not root:
        st.update({'ok': False, 'error': 'No cloud server address is set.', 'ts_try': cloudlib.now()})
        write_state(st)
        return st
    payload = {'install_id': install_id(), 'key': current_key(), 'version': plugin_version(),
               'hostname': os.uname().nodename[:64], 'os': ' '.join(os.uname()[:1] + os.uname()[2:3])[:40],
               'feeds': {'lastUpdate': last_feed_update()}}
    res = post(root + '/api/v1/checkin', payload)
    st['ts_try'] = cloudlib.now()
    if not res.get('ok'):
        st.update({'ok': False, 'error': res.get('error', 'the server did not accept the check-in')})
        write_state(st)
        return st
    lic = res.get('license') or {}
    st.update({'ok': True, 'error': '', 'ts': cloudlib.now(), 'server_state': lic.get('state', ''), 'server_message': lic.get('message', '')})
    now = php('status')
    try:
        if abs(int(res.get('server_time', 0)) - cloudlib.now()) < 600 and now.get('state') == 'rollback':
            now = php('resetseen')           # the vendor's clock agrees with ours: the clock is right, forget the old mark
    except (TypeError, ValueError):
        pass
    key_id = now.get('key_id', '')
    if lic.get('state') == 'revoked' and key_id:
        php('revoked', key_id, '1')
    elif lic.get('state') == 'active' and now.get('state') == 'revoked' and key_id:
        php('revoked', key_id, '0')
    update = res.get('update_key')
    if update and re.fullmatch(r'[A-Za-z2-7-]{100,400}', str(update)):
        act = php('activate', str(update))
        st['update'] = act.get('message', '')
    write_state(st)
    return st


def trial():
    cfg = cloudlib.settings()
    root = server_root(cfg)
    if not root:
        return {'ok': False, 'message': 'Enter the cloud server address first.'}
    res = post(root + '/api/v1/trial', {'install_id': install_id(), 'hostname': os.uname().nodename[:64]})
    if not res.get('ok'):
        return {'ok': False, 'message': res.get('error', 'The server did not issue a trial key.')}
    act = php('activate', str(res.get('key', '')))
    if act.get('ok'):
        checkin()
    return act if act else {'ok': False, 'message': 'The key could not be activated.'}


def status():
    st = read_state()
    st['feedUpdate'] = last_feed_update()
    return st


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'status'
    if cmd == 'checkin':
        print(json.dumps(checkin()))
    elif cmd == 'trial':
        print(json.dumps(trial()))
    else:
        print(json.dumps(status()))


if __name__ == '__main__':
    main()
