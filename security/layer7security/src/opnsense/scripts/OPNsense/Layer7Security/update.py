#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Updates: new releases of this plugin from the vendor's cloud server, and what OPNsense itself says
# about firmware and patch updates.
#
#   update.py check            ask the cloud server for the newest release (signed manifest)
#   update.py install          install the newest release now (blocks; the GUI uses install-async)
#   update.py install-async    same, detached; progress in the state and in update.log
#   update.py rollback         go back to the version that was installed before the last update (rollback-async: detached, for the GUI)
#   update.py auto             cron: check, and install when the owner switched automatic updates on
#   update.py firmware-check   let OPNsense check for firmware and package updates, then read the result
#   update.py firmware-update  install pending OPNsense package updates (patches); never reboots, never a major upgrade
#   update.py status           JSON for the GUI
#   update.py log              the last lines of update.log
#
# Trust: the manifest carries the vendor's signature (own signature domain, so a license or a support
# command cannot be taken for it); size and SHA-256 of the package come from the signed manifest, never
# from the download; a manifest older than one already seen is refused (no replay of an old release);
# nothing older than what is installed is ever installed by "update". Before an update the installed
# version is packed as a rollback copy; if the new version does not come up healthy, the old one is put back.

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cloudlib  # noqa: E402
import support  # noqa: E402

PKG_NAME = 'os-layer7security'
PKG = '/usr/sbin/pkg'
SERVICE = '/usr/sbin/service'
CONFIGCTL = '/usr/local/sbin/configctl'
STATE = os.path.join(cloudlib.BASE, 'update.json')
UPDATE_DIR = os.path.join(cloudlib.BASE, 'updates')
ROLLBACK_DIR = os.path.join(cloudlib.BASE, 'rollback')
LOG = os.path.join(cloudlib.BASE, 'update.log')
LOCK = os.path.join(cloudlib.BASE, 'update.lock')
FIRMWARE_JSON = '/tmp/pkg_upgrade.json'
DOMAIN_SEP = b'L7REL1\0'
MAX_PKG = 80 * 1024 * 1024
VERSION = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}(?:_\d{1,3})?$')
SHA = re.compile(r'^[0-9a-f]{64}$')


def now():
    return int(time.time())


def version_key(v):
    main, _, rev = str(v).partition('_')
    return tuple(int(x) for x in main.split('.')) + (int(rev or 0),)


def log(text):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, 'a') as f:
            f.write('%s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), text))
        with open(LOG) as f:
            lines = f.read().splitlines()
        if len(lines) > 400:
            with open(LOG, 'w') as f:
                f.write('\n'.join(lines[-300:]) + '\n')
    except OSError:
        pass


def read_state():
    try:
        with open(STATE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def write_state(st):
    support.write_private(STATE, json.dumps(st))


def update_state(**kw):
    st = read_state()
    st.update(kw)
    write_state(st)
    return st


def run(cmd, timeout=120):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode, (res.stdout or '') + (res.stderr or '')
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)


def settings():
    g = cloudlib.settings()['general']
    return {'channel': 'beta' if g.get('updateChannel') == 'beta' else 'stable', 'auto': g.get('autoUpdate') == '1', 'enabled': g.get('enabled') == '1'}


def installed_version():
    rc, out = run([PKG, 'query', '%v', PKG_NAME], 15)
    return out.strip().splitlines()[0][:20] if rc == 0 and out.strip() else ''


def opnsense_version():
    m = re.search(r'OPNsense\s+(\d+(?:\.\d+)*)', run(['/usr/local/sbin/opnsense-version'], 10)[1])
    return m.group(1) if m else ''


def at_least(have, need):
    """version 26.1.11 against a minimum such as 26.1"""
    try:
        a = [int(x) for x in re.findall(r'\d+', have)][:3]
        b = [int(x) for x in re.findall(r'\d+', need)][:3]
        return a + [0] * (3 - len(a)) >= b + [0] * (3 - len(b))
    except ValueError:
        return True


# ------------------------------------------------------------------ the signed manifest

def verify_manifest(doc):
    """-> (ok, reason)"""
    if not isinstance(doc, dict) or 'sig' not in doc:
        return False, 'the manifest is not signed'
    body = {k: doc.get(k) for k in ('v', 'product', 'issued', 'channels')}
    msg = json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    try:
        sig = base64.b64decode(str(doc['sig']), validate=True)
    except (ValueError, TypeError):
        return False, 'the signature is malformed'
    if len(sig) != 64:
        return False, 'the signature is malformed'
    with tempfile.TemporaryDirectory() as td:
        pub, m, s = (os.path.join(td, x) for x in ('pub.pem', 'm', 's'))
        with open(pub, 'w') as f:
            f.write(support.public_pem())
        with open(m, 'wb') as f:
            f.write(DOMAIN_SEP + msg)
        with open(s, 'wb') as f:
            f.write(sig)
        rc, _ = run([support.OPENSSL, 'pkeyutl', '-verify', '-pubin', '-inkey', pub, '-rawin', '-in', m, '-sigfile', s], 20)
    if rc != 0:
        return False, 'the signature is not the vendor\'s'
    if body['v'] != 1 or body['product'] != PKG_NAME:
        return False, 'the manifest is for something else'
    return True, ''


def clean_entry(e):
    """one release entry, only when every field is valid"""
    if not isinstance(e, dict):
        return None
    v = str(e.get('version', ''))
    if not VERSION.match(v) or str(e.get('file', '')) != '%s-%s.pkg' % (PKG_NAME, v) or not SHA.match(str(e.get('sha256', ''))):
        return None
    try:
        size = int(e.get('size'))
    except (TypeError, ValueError):
        return None
    if not 10000 <= size <= MAX_PKG:
        return None
    return {'version': v, 'file': str(e['file']), 'sha256': str(e['sha256']), 'size': size, 'notes': re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', str(e.get('notes', '')))[:2000],
            'released': int(e.get('released') or 0), 'min_opnsense': re.sub(r'[^0-9.]', '', str(e.get('min_opnsense', '')))[:20]}


def http_get(url, limit, timeout=60):
    req = urllib.request.Request(url, headers={'User-Agent': 'os-layer7security'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(limit + 1)
    if len(data) > limit:
        raise ValueError('the download is larger than allowed')
    return data


def server_root():
    base = cloudlib.base_url(cloudlib.settings())
    return re.sub(r'/feeds$', '', base) if base else ''


def check():
    """newest release from the cloud server; the answer is stored for the GUI and the reports"""
    cfg = settings()
    st = read_state()
    st.update({'channel': cfg['channel'], 'auto': cfg['auto'], 'installed': installed_version(), 'checked_try': now()})
    root = server_root()
    if not root:
        st['error'] = 'No cloud server address is set.'
        write_state(st)
        return st
    try:
        doc = json.loads(http_get(root + '/releases/manifest.json', 1 << 20, 30).decode('utf-8', 'replace'))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        st['error'] = 'cannot reach the update server (%s)' % str(getattr(exc, 'reason', exc))[:80]
        write_state(st)
        return st
    ok, why = verify_manifest(doc)
    if not ok:
        st['error'] = 'Refused: ' + why
        log('manifest refused: ' + why)
        write_state(st)
        return st
    try:
        issued = int(doc['issued'])
    except (TypeError, ValueError):
        issued = 0
    if issued < int(st.get('issued', 0)):
        st['error'] = 'Refused: the manifest is older than one already seen.'
        log('manifest refused: older than the last one')
        write_state(st)
        return st
    chans = doc.get('channels') if isinstance(doc.get('channels'), dict) else {}
    entry = clean_entry(chans.get(cfg['channel'])) or clean_entry(chans.get('stable'))
    st.update({'issued': issued, 'checked': now(), 'error': ''})
    if entry is None:
        st.update({'latest': '', 'available': False, 'entry': None, 'blocked': ''})
    else:
        newer = bool(st['installed']) and VERSION.match(st['installed'] or '') is not None and version_key(entry['version']) > version_key(st['installed'])
        blocked = ''
        if newer and entry['min_opnsense'] and not at_least(opnsense_version(), entry['min_opnsense']):
            blocked = 'Version %s needs OPNsense %s or newer.' % (entry['version'], entry['min_opnsense'])
        st.update({'latest': entry['version'], 'available': newer and not blocked, 'entry': entry, 'blocked': blocked, 'notes': entry['notes']})
    if st.get('state') == 'failed' and (entry is None or entry['version'] != st.get('target')):
        st.update({'state': 'idle', 'error': ''})                    # the release that failed is gone or replaced: try again
    elif st.get('state') not in ('installing', 'failed'):
        st['state'] = 'idle'
    write_state(st)
    return st


# ------------------------------------------------------------------ install and roll back

def lock():
    try:
        fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        try:
            with open(LOCK) as f:
                pid = int(f.read().strip() or 0)
            os.kill(pid, 0)
            if now() - os.stat(LOCK).st_mtime < 1800:
                return False
        except (OSError, ValueError):
            pass
        os.unlink(LOCK)
        return lock()
    os.write(fd, str(os.getpid()).encode())
    os.close(fd)
    return True


def unlock():
    try:
        os.unlink(LOCK)
    except OSError:
        pass


def download(entry, root):
    os.makedirs(UPDATE_DIR, exist_ok=True)
    os.chmod(UPDATE_DIR, 0o700)
    path = os.path.join(UPDATE_DIR, entry['file'])
    data = http_get('%s/releases/%s' % (root, entry['file']), entry['size'], 300)
    if len(data) != entry['size']:
        raise ValueError('the package has the wrong size')
    if hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise ValueError('the package does not match the signed checksum')
    with open(path + '.tmp', 'wb') as f:
        f.write(data)
    os.replace(path + '.tmp', path)
    return path


def after_install():
    """what a package installation does not do by itself on a running firewall"""
    for cmd in ([SERVICE, 'configd', 'restart'], [SERVICE, 'php_fpm', 'restart'], [CONFIGCTL, 'cron', 'restart'], [CONFIGCTL, 'layer7security', 'apply']):
        rc, out = run(cmd, 120)
        if rc != 0:
            log('%s failed: %s' % (' '.join(cmd[-2:]), out.strip()[:120]))
    time.sleep(2)


def healthy(expected_version):
    """the new version is installed and, when the plugin is on, its engine runs"""
    if installed_version() != expected_version:
        return False, 'the installed version is %s, not %s' % (installed_version() or 'unknown', expected_version)
    rc, out = run([CONFIGCTL, 'layer7security', 'license-status'], 60)
    try:
        json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return False, 'the plugin does not answer'
    if settings()['enabled']:
        for _ in range(8):
            rc, out = run([CONFIGCTL, 'layer7security', 'status'], 30)
            if 'is running' in out and 'not running' not in out:
                return True, ''
            time.sleep(3)
        return False, 'the engine is not running'
    return True, ''


def make_rollback_copy():
    """pack the installed version, so it can be put back without any server"""
    os.makedirs(ROLLBACK_DIR, exist_ok=True)
    os.chmod(ROLLBACK_DIR, 0o700)
    rc, out = run([PKG, 'create', '-o', ROLLBACK_DIR, PKG_NAME], 180)
    if rc != 0:
        return None
    copies = sorted((os.path.join(ROLLBACK_DIR, f) for f in os.listdir(ROLLBACK_DIR) if f.startswith(PKG_NAME + '-') and f.endswith(('.pkg', '.txz'))), key=os.path.getmtime)
    for old in copies[:-2]:
        try:
            os.unlink(old)
        except OSError:
            pass
    return copies[-1] if copies else None


def package_identity(path):
    """(name, version) of a package file as the package manager itself reads it, without installing anything"""
    rc, out = run([PKG, 'query', '-F', path, '%n %v'], 60)
    parts = out.strip().splitlines()[-1].split() if rc == 0 and out.strip() else []
    return (parts[0], parts[1]) if len(parts) == 2 else None


def pkg_add(path):
    rc, out = run([PKG, 'add', '-f', path], 300)
    return rc == 0, out.strip()[-300:]


def install(entry=None, quiet_lock=False):
    """-> dict with ok and message. Never leaves the plugin broken: a failed update is rolled back."""
    if not lock():
        return {'ok': False, 'message': 'An update is already running.'}
    before = installed_version()
    try:
        st = read_state()
        entry = entry or (st.get('entry') if st.get('available') else None)
        entry = clean_entry(entry)
        if entry is None or not before or version_key(entry['version']) <= version_key(before):
            return {'ok': False, 'message': 'There is no newer release to install.'}
        root = server_root()
        update_state(state='installing', error='', target=entry['version'], started=now())
        log('update %s -> %s: downloading' % (before, entry['version']))
        path = download(entry, root)
        ident = package_identity(path)
        if ident != (PKG_NAME, entry['version']):
            raise ValueError('the package says it is %s, not %s %s: nothing was changed' % (' '.join(ident) if ident else 'unreadable', PKG_NAME, entry['version']))
        backup = make_rollback_copy()
        if backup is None:
            raise ValueError('a rollback copy of the installed version could not be made, so nothing was changed')
        log('rollback copy: %s' % os.path.basename(backup))
        ok, out = pkg_add(path)
        after_install()
        good, why = healthy(entry['version']) if ok else (False, 'the package could not be installed: ' + out[-120:])
        if good:
            update_state(state='idle', error='', installed=entry['version'], available=False, rollback=before, finished=now())
            log('update done: %s' % entry['version'])
            return {'ok': True, 'message': 'Updated to %s.' % entry['version'], 'version': entry['version']}
        log('update failed (%s), rolling back to %s' % (why, before))
        pkg_add(backup)
        after_install()
        back, why2 = healthy(before)
        update_state(state='failed', error=('%s. Rolled back to %s.' % (why, before)) if back else ('%s. Putting back %s failed too (%s): repair needed.' % (why, before, why2)),
                     installed=installed_version(), finished=now())
        return {'ok': False, 'message': 'The update failed (%s) and %s.' % (why, 'the previous version was restored' if back else 'restoring it failed too')}
    except (ValueError, OSError, urllib.error.URLError) as exc:
        update_state(state='failed', error=str(getattr(exc, 'reason', exc))[:200], finished=now())
        log('update failed: %s' % exc)
        return {'ok': False, 'message': 'The update failed: %s' % str(getattr(exc, 'reason', exc))[:150]}
    finally:
        unlock()


def rollback():
    if not lock():
        return {'ok': False, 'message': 'An update is already running.'}
    try:
        copies = sorted((os.path.join(ROLLBACK_DIR, f) for f in os.listdir(ROLLBACK_DIR) if f.startswith(PKG_NAME + '-')), key=os.path.getmtime) if os.path.isdir(ROLLBACK_DIR) else []
        now_v = installed_version()
        copies = [c for c in copies if now_v and ('-%s.' % now_v) not in c]            # the copy of the current version is not a way back
        if not copies:
            return {'ok': False, 'message': 'There is no earlier version to go back to.'}
        target = re.search(r'-(\d+\.\d+\.\d+(?:_\d+)?)\.', os.path.basename(copies[-1]))
        want = target.group(1) if target else ''
        update_state(state='installing', error='')
        log('rollback to %s' % (want or copies[-1]))
        ok, out = pkg_add(copies[-1])
        after_install()
        good, why = healthy(want) if want else (ok, '')
        update_state(state='idle' if good else 'failed', error='' if good else 'Rollback problem: ' + why, installed=installed_version(), rollback='', available=False)
        unlock()
        check()                                                     # the release we just left is "available" again: say so
        return {'ok': good, 'message': ('Back to %s.' % want) if good else 'The rollback did not work: ' + why}
    finally:
        unlock()


def install_async():
    """start the update detached from the caller (the GUI request, the support poll loop)"""
    st = read_state()
    if st.get('state') == 'installing' and os.path.exists(LOCK):
        return {'ok': True, 'started': False, 'message': 'An update is already running.'}
    if not st.get('available'):
        st = check()
    if not st.get('available'):
        return {'ok': False, 'started': False, 'message': st.get('error') or st.get('blocked') or 'There is no newer release.'}
    update_state(state='installing', error='', target=st['latest'])
    subprocess.Popen([sys.executable, os.path.abspath(__file__), 'install'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    return {'ok': True, 'started': True, 'message': 'Updating to %s.' % st['latest']}


def rollback_async():
    """detached like install: the rollback restarts configd, which would cut off the caller's answer"""
    if os.path.exists(LOCK):
        return {'ok': False, 'started': False, 'message': 'An update is already running.'}
    copies = [f for f in os.listdir(ROLLBACK_DIR)] if os.path.isdir(ROLLBACK_DIR) else []
    if not any(f.startswith(PKG_NAME + '-') and ('-%s.' % installed_version()) not in f for f in copies):
        return {'ok': False, 'started': False, 'message': 'There is no earlier version to go back to.'}
    update_state(state='installing', error='')
    subprocess.Popen([sys.executable, os.path.abspath(__file__), 'rollback'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    return {'ok': True, 'started': True, 'message': 'Going back to the previous version.'}


def auto():
    st = check()
    try:
        firmware_check(240)
    except OSError:
        pass
    if settings()['auto'] and st.get('available') and not st.get('error'):
        log('automatic update to %s' % st['latest'])
        return install()
    return {'ok': True, 'message': 'checked'}


# ------------------------------------------------------------------ OPNsense firmware and patches

def firmware_busy():
    return 'busy' in run([CONFIGCTL, 'firmware', 'running'], 15)[1]


def firmware_status(check_busy=True):
    """what OPNsense found at its last check, from the file its own GUI reads"""
    try:
        with open(FIRMWARE_JSON) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return {'checked': 0, 'busy': firmware_busy() if check_busy else False, 'patch_count': 0, 'patches': [], 'major': None, 'needs_reboot': False}
    pk = d.get('upgrade_packages') if isinstance(d.get('upgrade_packages'), list) else []
    patches = [{'name': str(x.get('name', ''))[:48], 'from': str(x.get('current_version', ''))[:24], 'to': str(x.get('new_version', ''))[:24]}
               for x in pk if isinstance(x, dict)] + [{'name': str(x.get('name', ''))[:48], 'from': '', 'to': str(x.get('version', ''))[:24]}
                                                       for x in (d.get('new_packages') or []) if isinstance(x, dict)]
    major = None
    if d.get('upgrade_major_version'):
        msg = re.sub(r'<[^>]+>', ' ', str(d.get('upgrade_major_message', '')))
        major = {'version': str(d['upgrade_major_version'])[:12], 'eol': bool(re.search(r'end of life', msg, re.I)), 'note': re.sub(r'\s+', ' ', msg).strip()[:200]}
    checked = 0
    try:
        checked = int(time.mktime(time.strptime(str(d.get('last_check', '')).replace(' UTC', ''), '%a %b %d %H:%M:%S %Y')) - time.timezone)
    except ValueError:
        checked = int(os.path.getmtime(FIRMWARE_JSON))
    return {'checked': checked, 'version': str(d.get('product_version', ''))[:24], 'abi': str(d.get('product_abi', ''))[:12], 'patch_count': len(patches), 'patches': patches[:30],
            'download_size': str(d.get('download_size', ''))[:16], 'needs_reboot': str(d.get('needs_reboot', '0')) == '1', 'connection': str(d.get('connection', ''))[:12],
            'repository': str(d.get('repository', ''))[:12], 'major': major, 'busy': firmware_busy() if check_busy else False}


def firmware_check(wait=200):
    """ask OPNsense to look for updates and wait for it to finish"""
    if not firmware_busy():                                      # a check that is already running is only waited for
        run([CONFIGCTL, 'firmware', 'check'], 30)
    end = time.time() + wait
    time.sleep(3)
    while time.time() < end and firmware_busy():
        time.sleep(5)
    st = firmware_status()
    update_state(firmware_checked=now())
    return st


def firmware_update():
    """install the pending package updates; no reboot, no major upgrade"""
    st = firmware_status()
    if st['busy']:
        return {'ok': False, 'message': 'OPNsense is busy with an update or a check.'}
    if not st['patch_count']:
        return {'ok': False, 'message': 'There are no updates waiting (check first).'}
    log('OPNsense update of %d package(s) started' % st['patch_count'])
    subprocess.Popen([CONFIGCTL, 'firmware', 'update'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, start_new_session=True)
    return {'ok': True, 'message': 'Updating %d package(s). A restart is not done automatically.' % st['patch_count']}


def start_detached(arg):
    subprocess.Popen([sys.executable, os.path.abspath(__file__), arg], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


# ------------------------------------------------------------------ views

def summary():
    """for the monitoring report: no network, only what is stored"""
    st = read_state()
    fw = firmware_status(False) if os.path.exists(FIRMWARE_JSON) else {'checked': 0, 'patch_count': 0, 'patches': [], 'major': None, 'needs_reboot': False}
    return {'plugin': {'installed': st.get('installed') or installed_version(), 'latest': st.get('latest', ''), 'available': bool(st.get('available')), 'channel': st.get('channel', 'stable'),
                       'checked': st.get('checked', 0), 'state': st.get('state', 'idle'), 'error': st.get('error', ''), 'auto': bool(st.get('auto')),
                       'rollback': st.get('rollback', '')},
            'firmware': fw}


def status():
    d = summary()
    st = read_state()
    d['plugin'].update({'notes': st.get('notes', ''), 'blocked': st.get('blocked', ''), 'target': st.get('target', ''), 'released': (st.get('entry') or {}).get('released', 0)})
    d['settings'] = settings()
    d['opnsense'] = opnsense_version()
    try:
        with open(LOG) as f:
            d['log'] = f.read().splitlines()[-8:]
    except OSError:
        d['log'] = []
    return d


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'status'
    if cmd == 'check':
        st = check()
        print(json.dumps({'ok': not st.get('error'), 'error': st.get('error', ''), 'installed': st.get('installed'), 'latest': st.get('latest'), 'available': st.get('available')}))
    elif cmd == 'install':
        print(json.dumps(install()))
    elif cmd == 'install-async':
        print(json.dumps(install_async()))
    elif cmd == 'rollback':
        print(json.dumps(rollback()))
    elif cmd == 'rollback-async':
        print(json.dumps(rollback_async()))
    elif cmd == 'auto':
        print(json.dumps(auto()))
    elif cmd == 'firmware-check':
        print(json.dumps(firmware_check()))
    elif cmd == 'firmware-update':
        print(json.dumps(firmware_update()))
    elif cmd == 'log':
        try:
            with open(LOG) as f:
                lines = f.read().splitlines()[-40:]
        except OSError:
            lines = []
        print(json.dumps({'lines': lines}))
    else:
        print(json.dumps(status()))


if __name__ == '__main__':
    main()
