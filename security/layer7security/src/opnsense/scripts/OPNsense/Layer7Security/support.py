#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Remote support, firewall side: runs the commands the vendor sends from L7 Cloud, but only
# when every check passes:
#   1. the signature is the vendor's (Ed25519, domain separated from license keys),
#   2. the command is for this firewall, is at most 15 minutes old, not expired and never seen,
#   3. the action is on the fixed list and its parameters are valid,
#   4. the owner of this firewall allows it right now (Layer 7 > License > Remote support:
#      off, view or manage), checked again at the moment of running.
# Every command, run or refused, is written to the audit log that the owner can read in the GUI.
# Nothing is ever passed to a shell.
#
#   support.py log [N]       the audit log as JSON (newest first)
#   support.py level         the level the owner allows

import base64
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cloudlib  # noqa: E402

LICENSE_CLASS = '/usr/local/opnsense/mvc/app/library/OPNsense/Layer7Security/License.php'
SUPPORT_PHP = '/usr/local/opnsense/scripts/OPNsense/Layer7Security/support.php'
CONFIGCTL = '/usr/local/sbin/configctl'
OPENSSL = os.environ.get('L7_OPENSSL', '/usr/bin/openssl')
ENGINE_DB = '/var/db/layer7security/l7.db'
AUDIT = os.path.join(cloudlib.BASE, 'support_audit.jsonl')
SEEN = os.path.join(cloudlib.BASE, 'support_seen.json')
PENDING = os.path.join(cloudlib.BASE, 'support_pending.json')
DOMAIN_SEP = b'L7CMD1\0'
LEVELS = ('off', 'view', 'manage')
MAX_AGE = 900
MAX_RESULT = 200 * 1024
KEEP_AUDIT = 500
READ = {'overview', 'config', 'sites', 'events', 'audit', 'updates'}
WRITE = {'web_rule', 'set_option', 'toggle_item', 'apply', 'feed_update', 'restart_engine', 'plugin_update', 'firmware_check', 'firmware_update'}
OPTION_PATHS = ('general.enabled', 'general.enforce', 'general.retention', 'general.flowTimeout', 'general.blockTtl', 'general.dnsFilter',
                'general.dnsMode', 'general.dnsCategories', 'general.dnsBlock', 'general.dnsAllow', 'general.geoEnabled', 'general.aiEnabled',
                'general.aiDefault', 'general.aiQuic', 'webcontrol.enabled', 'cfs.safeSearch', 'cfs.youtube', 'cfs.threatIps', 'cfs.threatDirection')
SECTIONS = ('policies', 'webcontrol', 'bindings', 'geo', 'users')
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
SITE = re.compile(r'^(?:\*\.?)?[a-z0-9?*]([a-z0-9._?*-]{0,250}[a-z0-9?*])?$|^[0-9a-f:.]{2,45}(?:/[0-9]{1,3})?$', re.I)
# whatever looks like a secret never leaves the firewall
SECRET = re.compile(r'key|secret|token|passw|hash|pem|cert|salt', re.I)


def now():
    return int(time.time())


def need_level(action):
    return 'view' if action in READ else 'manage' if action in WRITE else None


def allows(level, need):
    return level in LEVELS and level != 'off' and LEVELS.index(level) >= LEVELS.index(need)


def local_level():
    lvl = cloudlib.settings()['general'].get('remoteSupport') or 'off'
    return lvl if lvl in LEVELS else 'off'


# ------------------------------------------------------------------ parameters (the same rules as the server, checked again here)

def clean_int(v, lo, hi, default):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def printable(v, n):
    return re.sub(r'[^\x20-\x7e]', '', str(v if v is not None else ''))[:n]


def clean_params(action, p):
    p = p if isinstance(p, dict) else {}
    if action == 'sites':
        return {'hours': clean_int(p.get('hours'), 1, 168, 24), 'limit': clean_int(p.get('limit'), 1, 100, 30)}
    if action == 'events':
        return {'limit': clean_int(p.get('limit'), 1, 200, 50)}
    if action == 'web_rule':
        op = str(p.get('op', ''))
        if op not in ('add', 'remove', 'enable', 'disable'):
            raise ValueError('bad operation')
        if op != 'add':
            if not UUID.match(str(p.get('uuid', ''))):
                raise ValueError('bad rule id')
            return {'op': op, 'uuid': str(p['uuid'])}
        value = printable(p.get('value'), 253).strip().lower()
        if not value or not SITE.match(value):
            raise ValueError('bad site or address')
        return {'op': 'add', 'kind': 'ip' if p.get('kind') == 'ip' else 'domain', 'value': value,
                'rule_action': 'allow' if p.get('rule_action') == 'allow' else 'block', 'minutes': clean_int(p.get('minutes'), 0, 525600, 0),
                'note': printable(p.get('note'), 120)}
    if action == 'set_option':
        if str(p.get('path', '')) not in OPTION_PATHS:
            raise ValueError('option not allowed')
        return {'path': str(p['path']), 'value': printable(p.get('value'), 4000)}
    if action == 'toggle_item':
        if str(p.get('section', '')) not in SECTIONS or not UUID.match(str(p.get('uuid', ''))):
            raise ValueError('bad item')
        return {'section': str(p['section']), 'uuid': str(p['uuid']), 'enabled': '1' if str(p.get('enabled')) in ('1', 'true', 'True') else '0'}
    return {}


# ------------------------------------------------------------------ verification

def public_pem():
    """the vendor key that is built into License.php, as PEM"""
    override = os.environ.get('L7_SUPPORT_PUBPEM')
    if override:
        with open(override) as f:
            return f.read()
    with open(LICENSE_CLASS) as f:
        m = re.search(r"PUBKEY_B64\s*=\s*'([A-Za-z0-9+/=]{44})'", f.read())
    if not m:
        raise RuntimeError('no vendor key')
    der = bytes.fromhex('302a300506032b6570032100') + base64.b64decode(m.group(1))
    b64 = base64.b64encode(der).decode()
    return '-----BEGIN PUBLIC KEY-----\n' + b64 + '\n-----END PUBLIC KEY-----\n'


def canonical(body):
    return json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def verify_signature(body, sig_b64):
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except (ValueError, TypeError):
        return False
    if len(sig) != 64:
        return False
    with tempfile.TemporaryDirectory() as td:
        pub, msg, sg = (os.path.join(td, x) for x in ('pub.pem', 'm', 's'))
        with open(pub, 'w') as f:
            f.write(public_pem())
        with open(msg, 'wb') as f:
            f.write(DOMAIN_SEP + canonical(body).encode())
        with open(sg, 'wb') as f:
            f.write(sig)
        try:
            res = subprocess.run([OPENSSL, 'pkeyutl', '-verify', '-pubin', '-inkey', pub, '-rawin', '-in', msg, '-sigfile', sg],
                                 capture_output=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            return False
        return res.returncode == 0


def load_seen():
    try:
        with open(SEEN) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def remember(cmd_id, exp):
    seen = {k: v for k, v in load_seen().items() if v > now() - 2 * MAX_AGE}
    seen[cmd_id] = max(int(exp), now())
    if len(seen) > 500:
        seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-300:])
    write_private(SEEN, json.dumps(seen))


def write_private(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(text)
    os.replace(tmp, path)


def verify(env, install_id):
    """-> (ok, reason). Everything that makes a command trustworthy, in one place."""
    if not isinstance(env, dict):
        return False, 'not a command'
    keys = ('v', 'id', 'fw', 'action', 'params', 'level', 'iat', 'exp')
    body = {k: env.get(k) for k in keys}
    if any(env.get(k) is None for k in keys):
        return False, 'incomplete command'
    if not verify_signature(body, str(env.get('sig', ''))):
        return False, 'the signature is not the vendor\'s'
    if body['v'] != 1 or not re.fullmatch(r'[0-9a-f]{24}', str(body['id'])):
        return False, 'unknown command format'
    if body['fw'] != install_id:
        return False, 'meant for another firewall'
    try:
        iat, exp = int(body['iat']), int(body['exp'])
    except (TypeError, ValueError):
        return False, 'bad times'
    t = now()
    if iat > t + 120:
        return False, 'issued in the future (clock?)'
    if exp < t:
        return False, 'expired'
    if exp - iat > MAX_AGE:
        return False, 'valid for too long'
    need = need_level(str(body['action']))
    if need is None:
        return False, 'unknown action'
    if body['level'] != need:
        return False, 'the level does not match the action'
    if str(body['id']) in load_seen():
        return False, 'this command was already seen (replay)'
    return True, ''


# ------------------------------------------------------------------ audit

def audit(entry):
    entry = dict(entry, ts=now())
    try:
        lines = []
        try:
            with open(AUDIT) as f:
                lines = f.read().splitlines()[-(KEEP_AUDIT - 1):]
        except OSError:
            pass
        lines.append(json.dumps(entry, sort_keys=True))
        write_private(AUDIT, '\n'.join(lines) + '\n')
    except OSError:
        pass


def audit_tail(limit=50):
    rows = []
    try:
        with open(AUDIT) as f:
            for line in f.read().splitlines()[-limit:]:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    return rows[::-1]


def summary(action, params):
    """short text for the audit log; never contains anything secret"""
    if action == 'web_rule':
        return ' '.join(str(params.get(k, '')) for k in ('op', 'rule_action', 'value', 'uuid') if params.get(k))[:120]
    if action == 'set_option':
        return '%s = %s' % (params.get('path'), str(params.get('value'))[:60])
    if action == 'toggle_item':
        return '%s %s enabled=%s' % (params.get('section'), params.get('uuid'), params.get('enabled'))
    return ' '.join('%s=%s' % kv for kv in sorted(params.items()))[:120]


# ------------------------------------------------------------------ read actions

def config_tree():
    """the plugin configuration as JSON without anything that looks like a secret"""
    try:
        root = ET.parse(cloudlib.CONFIG).getroot().find('./OPNsense/layer7security')
    except (OSError, ET.ParseError):
        return {}
    if root is None:
        return {}

    def node(el):
        kids = list(el)
        if not kids:
            return (el.text or '').strip()[:2000]
        out, arrays = {}, {}
        for k in kids:
            if SECRET.search(k.tag):
                continue
            if k.get('uuid'):
                item = node(k)
                if isinstance(item, dict):
                    item = dict(item, uuid=k.get('uuid'))
                arrays.setdefault(k.tag, []).append(item)
            else:
                out[k.tag] = node(k)
        out.update(arrays)
        return out
    return node(root)


def engine():
    if not os.path.exists(ENGINE_DB):
        return None
    con = sqlite3.connect('file:%s?mode=ro' % ENGINE_DB, uri=True, timeout=3)
    con.row_factory = sqlite3.Row
    return con


def read_overview():
    tree = config_tree()
    general = {k: v for k, v in (tree.get('general') or {}).items() if k != 'feedUrl' and not isinstance(v, (dict, list))}
    counts = {'policies': len((tree.get('policies') or {}).get('policy', [])), 'webRules': len((tree.get('webcontrol') or {}).get('rule', [])),
              'users': len((tree.get('users') or {}).get('user', [])), 'macBindings': len((tree.get('bindings') or {}).get('binding', [])),
              'geoPolicies': len((tree.get('geo') or {}).get('policy', []))}
    st = {}
    try:
        with open('/var/run/layer7security/status.json') as f:
            st = json.load(f)
    except (OSError, ValueError):
        pass
    lic = {}
    try:
        with open(os.path.join(cloudlib.BASE, 'license_cloud.json')) as f:
            lic = json.load(f)
    except (OSError, ValueError):
        pass
    agent = {}
    try:
        with open(os.path.join(cloudlib.BASE, 'agent.json')) as f:
            a = json.load(f)
        agent = {'lastOk': a.get('last_ok'), 'error': a.get('error')}
    except (OSError, ValueError):
        pass
    return {'general': general, 'counts': counts, 'engine': {k: st.get(k) for k in ('version', 'started', 'flows_active', 'blocks', 'packets', 'policies')},
            'license': {'serverState': lic.get('server_state'), 'lastCheckin': lic.get('ts')}, 'agent': agent,
            'feeds': {'lastUpdate': cloudlib.load_state().get('manifest', {})}, 'time': now()}


def read_sites(hours, limit):
    tree = config_tree()
    rules = [r for r in (tree.get('webcontrol') or {}).get('rule', []) if isinstance(r, dict)]
    out = {'hours': hours, 'rules': rules, 'blocked': [], 'allowed': []}
    con = engine()
    if con is None:
        return out
    since = now() - hours * 3600
    try:
        out['blocked'] = [dict(r) for r in con.execute(
            "SELECT host, category, policy, COUNT(*) hits, MAX(ts) last FROM events WHERE type='block' AND ts >= ? AND host != '' "
            "GROUP BY host, category, policy ORDER BY hits DESC LIMIT ?", (since, limit))]
        out['allowed'] = [dict(r) for r in con.execute(
            "SELECT host, app, category, COUNT(*) hits, COUNT(DISTINCT client) clients, SUM(bytes_up + bytes_down) bytes FROM flows "
            "WHERE ts_end >= ? AND host != '' AND (action IS NULL OR action != 'block') GROUP BY host, app, category ORDER BY hits DESC LIMIT ?",
            (since, limit))]
    finally:
        con.close()
    return out


def read_events(limit, with_client):
    con = engine()
    if con is None:
        return {'rows': []}
    try:
        cols = 'ts, type, app, category, host, policy, detail' + (', client' if with_client else '')
        return {'rows': [dict(r) for r in con.execute('SELECT %s FROM events ORDER BY id DESC LIMIT ?' % cols, (limit,))], 'clients': with_client}
    finally:
        con.close()


# ------------------------------------------------------------------ write actions

def php(cmd, params):
    try:
        res = subprocess.run(['/usr/local/bin/php', SUPPORT_PHP, cmd, json.dumps(params)], capture_output=True, text=True, timeout=120)
        out = (res.stdout or '').strip().splitlines()
        d = json.loads(out[-1]) if out else {}
        return bool(d.get('ok')), str(d.get('message', 'no answer'))[:300], d
    except (OSError, subprocess.SubprocessError, ValueError):
        return False, 'the change could not be made', {}


def configd(*args):
    try:
        res = subprocess.run([CONFIGCTL, 'layer7security'] + list(args), capture_output=True, text=True, timeout=300)
        return res.returncode == 0, (res.stdout or res.stderr or '').strip()[:200]
    except (OSError, subprocess.SubprocessError):
        return False, 'the command could not be run'


def run_action(action, params, level):
    """-> (ok, message, data)"""
    if action == 'overview':
        return True, 'Overview read.', read_overview()
    if action == 'config':
        return True, 'Settings read.', config_tree()
    if action == 'sites':
        return True, 'Sites read.', read_sites(params['hours'], params['limit'])
    if action == 'events':
        return True, 'Events read.', read_events(params['limit'], level == 'manage')
    if action == 'audit':
        return True, 'Support log read.', {'rows': audit_tail(100)}
    if action in ('web_rule', 'set_option', 'toggle_item'):
        ok, msg, data = php(action, params)
        return ok, msg, None
    if action == 'apply':
        ok, msg = configd('apply')
        return ok, 'Configuration applied.' if ok else 'Apply failed: ' + msg, None
    if action == 'feed_update':
        ok, msg = configd('feed-update-parts', 'domains,ips,hashes,signatures')
        return ok, 'Lists updated.' if ok else 'Update failed: ' + msg, None
    if action == 'updates':
        import update                                            # imported here: update.py itself imports this module
        return True, 'Update status read.', update.status()
    if action == 'plugin_update':
        import update
        res = update.install_async()
        return bool(res.get('ok')), str(res.get('message', ''))[:200], None
    if action == 'firmware_check':
        import update
        update.start_detached('firmware-check')
        return True, 'OPNsense is checking for updates. Read the update status in about two minutes.', None
    if action == 'firmware_update':
        import update
        res = update.firmware_update()
        return bool(res.get('ok')), str(res.get('message', ''))[:200], None
    if action == 'restart_engine':
        ok, msg = configd('restart')
        return ok, 'Engine restarted.' if ok else 'Restart failed: ' + msg, None
    return False, 'unknown action', None


def execute(env, install_id):
    """verify, check consent, run, audit; always returns a result for the server"""
    ok, why = verify(env, install_id)
    cmd_id = str(env.get('id', ''))[:24] if isinstance(env, dict) else ''
    action = str(env.get('action', ''))[:24] if isinstance(env, dict) else ''
    if not ok:
        audit({'id': cmd_id, 'action': action, 'ok': False, 'result': 'refused: ' + why, 'detail': ''})
        return {'id': cmd_id, 'ok': False, 'message': 'Refused by the firewall: ' + why}
    remember(env['id'], env['exp'])                           # a command is used at most once, whatever happens next
    level = local_level()
    need = need_level(action)
    try:
        params = clean_params(action, env.get('params'))
    except ValueError as exc:
        audit({'id': cmd_id, 'action': action, 'ok': False, 'result': 'refused: ' + str(exc), 'detail': ''})
        return {'id': cmd_id, 'ok': False, 'message': 'Refused by the firewall: ' + str(exc)}
    if not allows(level, need):
        msg = 'remote support is switched off here' if level == 'off' else 'the owner only allows viewing'
        audit({'id': cmd_id, 'action': action, 'ok': False, 'result': 'refused: ' + msg, 'detail': summary(action, params)})
        return {'id': cmd_id, 'ok': False, 'message': 'Refused by the firewall: ' + msg}
    try:
        good, message, data = run_action(action, params, level)
    except Exception as exc:                                  # whatever goes wrong is reported, never raised
        good, message, data = False, 'failed: %s' % str(exc)[:150], None
    audit({'id': cmd_id, 'action': action, 'ok': good, 'result': message[:200], 'detail': summary(action, params)})
    out = {'id': cmd_id, 'ok': good, 'message': message}
    if data is not None:
        blob = json.dumps(data)
        out['data'] = data if len(blob) <= MAX_RESULT else {'truncated': True, 'note': 'The answer was too large to send.'}
    return out


# ------------------------------------------------------------------ polling (called by agent.py)

def load_pending():
    try:
        with open(PENDING) as f:
            d = json.load(f)
        return d if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def poll_loop(post, root, install_id, token, budget=48):
    """fast polling while the vendor has the support page open or work is waiting"""
    end = time.time() + budget
    results = load_pending()
    while True:
        level = local_level()
        res = post(root + '/api/v1/support/poll', {'install_id': install_id, 'level': level, 'results': results}, token, 25)
        if not res.get('ok'):
            write_private(PENDING, json.dumps(results[-10:]))
            return {'ok': False, 'error': res.get('error', '')}
        results = []
        commands = res.get('commands') if isinstance(res.get('commands'), list) else []
        for env in commands[:5]:
            results.append(execute(env, install_id))
        if os.path.exists(PENDING):
            try:
                os.unlink(PENDING)
            except OSError:
                pass
        if time.time() >= end and not results:
            return {'ok': True}
        if not commands and not results:
            time.sleep(3)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'level'
    if cmd == 'log':
        try:
            n = max(1, min(200, int(sys.argv[2])))
        except (IndexError, ValueError):
            n = 50
        print(json.dumps({'rows': audit_tail(n), 'level': local_level()}))
    else:
        print(json.dumps({'level': local_level()}))


if __name__ == '__main__':
    main()
