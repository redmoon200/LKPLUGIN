#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Downloads what the cloud feed server offers: website category lists, IP
# threat lists, malware hashes and antivirus signatures.
#
#   feed_update.py update [parts]   parts: domains,ips,hashes,signatures (default all)
#   feed_update.py auto             the same, silent, only when a feed is configured and the data is due
#   feed_update.py fill             only what is enabled but still missing (used by Apply)
#   feed_update.py status           what is installed: counts and ages (JSON)
#
# Prints JSON. Rebuilds the Unbound filter, reloads the pf tables and tells the
# ICAP scanner when something changed.

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cloudlib  # noqa: E402
import signatures  # noqa: E402

LIST_DIR = os.path.join(cloudlib.BASE, 'lists')
THREAT_DIR = os.path.join(cloudlib.BASE, 'threat')
AV_DIR = os.path.join(cloudlib.BASE, 'av')
SEED_DIR = '/usr/local/share/layer7security/seeds'
CATEGORIES = ['ads', 'trackers', 'malware', 'phishing', 'adult', 'gambling', 'social', 'streaming', 'games', 'botnet']
IP_LISTS = ['c2', 'compromised', 'attackers', 'drop', 'tor']
HASH_ALGOS = {'sha256': 64, 'sha1': 40, 'md5': 32}
DOMAIN = re.compile(r'^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$')
IPNET = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$')
FAMILY = re.compile(r'[^A-Za-z0-9_. -]')
PARTS = ('domains', 'ips', 'hashes', 'signatures')
# how often each part is refreshed by the scheduled job (hours)
DUE_HOURS = {'domains': 6, 'ips': 3, 'hashes': 3, 'signatures': 12}


def parse_list(text):
    """accept plain domain lists and hosts-file lines ("0.0.0.0 domain")"""
    domains = set()
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip().lower()
        if not line:
            continue
        parts = line.split()
        name = parts[-1]
        if len(parts) == 2 and parts[0] not in ('0.0.0.0', '127.0.0.1', '::', '::1'):
            continue
        if name in ('localhost', 'local', 'broadcasthost') or not DOMAIN.match(name):
            continue
        domains.add(name)
    return domains


def parse_hashes(text, width):
    """lines "hash" or "hash;family" with a hash of the given hex length"""
    keep = []
    pat = re.compile(r'^[0-9a-f]{%d}$' % width)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        h, _sep, fam = line.partition(';')
        h = h.strip().lower()
        if pat.match(h):
            fam = FAMILY.sub('', fam)[:40].strip()
            keep.append(h + (';' + fam if fam else ''))
    return keep


def enabled_ip_lists(cfg):
    return [x for x in (cfg['cfs'].get('threatIps') or '').split(',') if x in IP_LISTS]


def update_domains(base, state, force):
    out = []
    changed = False
    st = state.setdefault('domains', {})
    os.makedirs(LIST_DIR, exist_ok=True)
    for cat in CATEGORIES:
        item = {'category': cat}
        try:
            prev = st.get(cat, {})
            path = os.path.join(LIST_DIR, cat + '.txt')
            use_etag = None if force or not os.path.exists(path) else prev.get('etag')
            status, raw, etag = cloudlib.get('%s/%s.txt' % (base, cat), use_etag)
            if status == 200:
                domains = parse_list(raw.decode('utf-8', 'replace'))
                body = ''.join(d + '\n' for d in sorted(domains))
                old = open(path).read() if os.path.exists(path) else None
                if old != body:
                    cloudlib.write_atomic(path, body)
                    changed = True
                st[cat] = {'etag': etag, 'ts': cloudlib.now(), 'count': len(domains)}
                item.update(ok=True, domains=len(domains))
            else:
                st.setdefault(cat, {})['ts'] = cloudlib.now()
                item.update(ok=True, domains=prev.get('count', 0), unchanged=True)
        except Exception as exc:  # network and parse errors are reported per list
            if getattr(exc, 'code', 0) == 404:
                item.update(ok=False, error='not offered by this server')
            else:
                item.update(ok=False, error=str(exc)[:120])
        out.append(item)
    return out, changed


def reload_table(table, path):
    subprocess.run(['/sbin/pfctl', '-q', '-t', table, '-T', 'replace', '-f', path], capture_output=True, timeout=60)


def update_ips(base, state, cfg, force, only_missing=False):
    out = []
    changed = False
    st = state.setdefault('ips', {})
    os.makedirs(THREAT_DIR, exist_ok=True)
    want = enabled_ip_lists(cfg)
    for lid in IP_LISTS:
        path = os.path.join(THREAT_DIR, lid + '.txt')
        have = os.path.exists(path) and os.path.getsize(path) > 0
        if lid not in want and not (have and not only_missing):
            continue
        if only_missing and have:
            continue
        item = {'list': lid}
        try:
            prev = st.get(lid, {})
            status, raw, etag = cloudlib.get('%s/ip/%s.txt' % (base, lid), None if force or not have else prev.get('etag'))
            if status == 200:
                nets = sorted({x for x in raw.decode('utf-8', 'replace').split() if IPNET.match(x)})
                if not nets:
                    raise ValueError('the list is empty')
                body = ''.join(n + '\n' for n in nets)
                old = open(path).read() if have else None
                if old != body:
                    cloudlib.write_atomic(path, body)
                    changed = True
                    if lid in want:
                        reload_table('l7_thr_' + lid, path)
                st[lid] = {'etag': etag, 'ts': cloudlib.now(), 'count': len(nets)}
                item.update(ok=True, entries=len(nets))
            else:
                st.setdefault(lid, {})['ts'] = cloudlib.now()
                item.update(ok=True, entries=prev.get('count', 0), unchanged=True)
        except Exception as exc:
            item.update(ok=False, error=str(exc)[:120])
        out.append(item)
    return out, changed


def update_hashes(base, state, force):
    out = []
    changed = False
    st = state.setdefault('hashes', {})
    os.makedirs(AV_DIR, exist_ok=True)
    for algo, width in HASH_ALGOS.items():
        item = {'algo': algo}
        path = os.path.join(AV_DIR, 'cloud_%s.txt' % algo)
        try:
            prev = st.get(algo, {})
            use_etag = None if force or not os.path.exists(path) else prev.get('etag')
            status, raw, etag = cloudlib.get('%s/hashes/%s.txt' % (base, algo), use_etag)
            if status == 200:
                keep = parse_hashes(raw.decode('utf-8', 'replace'), width)
                if not keep:
                    raise ValueError('no valid hashes in the download')
                body = '\n'.join(keep) + '\n'
                old = open(path).read() if os.path.exists(path) else None
                if old != body:
                    cloudlib.write_atomic(path, body)
                    changed = True
                st[algo] = {'etag': etag, 'ts': cloudlib.now(), 'count': len(keep)}
                item.update(ok=True, hashes=len(keep))
            else:
                st.setdefault(algo, {})['ts'] = cloudlib.now()
                item.update(ok=True, hashes=prev.get('count', 0), unchanged=True)
        except Exception as exc:
            if getattr(exc, 'code', 0) == 404:
                item.update(ok=False, error='not offered by this server')
            else:
                item.update(ok=False, error=str(exc)[:120])
        out.append(item)
    return out, changed


def update_signatures(base, state):
    try:
        res = signatures.update(base)
        state['signatures'] = {'ts': cloudlib.now(), 'usable': res.get('usable', 0), 'rejected': res.get('rejected', 0),
                               'ok': bool(res.get('ok')), 'error': res.get('error', '')}
        return res, bool(res.get('fetched') or res.get('removed'))
    except Exception as exc:
        state['signatures'] = dict(state.get('signatures', {}), ok=False, error=str(exc)[:160], ts=cloudlib.now())
        return {'ok': False, 'error': str(exc)[:160]}, False


def due(state, part):
    """does the scheduled job have to refresh this part"""
    if part == 'signatures':
        ts = state.get('signatures', {}).get('ts', 0)
    else:
        ts = min([v.get('ts', 0) for v in state.get(part, {}).values()] or [0])
    return cloudlib.now() - ts >= DUE_HOURS[part] * 3600 - 300


def update(parts, quiet, only_missing=False, force=False):
    cfg = cloudlib.settings()
    base = cloudlib.base_url(cfg)
    if not base:
        return {'result': 'skipped', 'message': 'no cloud feed URL configured'} if not quiet else {'result': 'skipped'}
    state = cloudlib.load_state()
    result = {'result': 'ok', 'ts': cloudlib.now(), 'base': base}
    changed = {}
    use_av = cfg['av'].get('enabled') == '1' and cfg['av'].get('useCloud', '1') == '1'
    for part in parts:
        if quiet and not only_missing and not due(state, part):
            continue
        if part == 'domains':
            if only_missing and all(os.path.exists(os.path.join(LIST_DIR, c + '.txt')) for c in CATEGORIES):
                continue
            result['domains'], changed['domains'] = update_domains(base, state, force)
        elif part == 'ips':
            result['ips'], changed['ips'] = update_ips(base, state, cfg, force, only_missing)
        elif part == 'hashes':
            if not use_av or (only_missing and os.path.exists(os.path.join(AV_DIR, 'cloud_md5.txt'))):
                continue
            result['hashes'], changed['hashes'] = update_hashes(base, state, force)
        elif part == 'signatures':
            if not use_av or cfg['av'].get('yaraAction', 'monitor') == 'off':
                continue
            if only_missing and os.path.exists(signatures.RULES):
                continue
            result['signatures'], changed['signatures'] = update_signatures(base, state)
    try:
        man = cloudlib.get(base + '/manifest.json', timeout=20)[1]
        if man:
            m = json.loads(man.decode('utf-8', 'replace'))
            state['manifest'] = {'built': m.get('built', 0), 'version': m.get('version', 1)}
    except Exception:
        pass
    cloudlib.save_state(state)
    if changed.get('domains') and cfg['general'].get('dnsFilter') == '1' and not only_missing:
        subprocess.run(['/usr/local/opnsense/scripts/OPNsense/Layer7Security/apply.php', '--dns-only'],
                       check=False, stdout=subprocess.DEVNULL)
    if changed.get('hashes') or changed.get('signatures'):
        subprocess.run(['/usr/bin/pkill', '-HUP', '-f', 'icap_server.py'], check=False)
    rows = [r for k in ('domains', 'ips', 'hashes') for r in result.get(k, [])]
    ok = [r for r in rows if r.get('ok')]
    result['updated'] = len(ok)
    result['failed'] = len(rows) - len(ok)
    result['total'] = len(rows)
    result['lists'] = result.get('domains', [])      # field read by older GUI code
    if rows and not ok and not result.get('signatures', {}).get('ok'):
        result['result'] = 'failed'
    return result


def status():
    cfg = cloudlib.settings()
    state = cloudlib.load_state()
    domains = []
    for cat in CATEGORIES:
        lst = os.path.join(LIST_DIR, cat + '.txt')
        domains.append({'category': cat, 'seed': cloudlib.count_lines(os.path.join(SEED_DIR, cat + '.txt')),
                        'feed': cloudlib.count_lines(lst),
                        'updated': int(os.path.getmtime(lst)) if os.path.exists(lst) else 0,
                        'checked': state.get('domains', {}).get(cat, {}).get('ts', 0)})
    ips = []
    want = enabled_ip_lists(cfg)
    for lid in IP_LISTS:
        path = os.path.join(THREAT_DIR, lid + '.txt')
        ips.append({'list': lid, 'enabled': lid in want, 'entries': cloudlib.count_lines(path),
                    'updated': int(os.path.getmtime(path)) if os.path.exists(path) else 0,
                    'checked': state.get('ips', {}).get(lid, {}).get('ts', 0)})
    hashes = {}
    for algo in HASH_ALGOS:
        path = os.path.join(AV_DIR, 'cloud_%s.txt' % algo)
        hashes[algo] = {'count': cloudlib.count_lines(path),
                        'updated': int(os.path.getmtime(path)) if os.path.exists(path) else 0,
                        'checked': state.get('hashes', {}).get(algo, {}).get('ts', 0)}
    sig = signatures.status()
    sig['error'] = state.get('signatures', {}).get('error', '')
    return {'lists': domains, 'domains': domains, 'ips': ips, 'hashes': hashes, 'signatures': sig,
            'feedUrl': cloudlib.base_url(cfg), 'manifest': state.get('manifest', {})}


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'status'
    if cmd == 'status':
        print(json.dumps(status()))
    elif cmd in ('update', 'auto', 'fill'):
        parts = [p for p in (sys.argv[2].split(',') if len(sys.argv) > 2 else PARTS) if p in PARTS] or list(PARTS)
        print(json.dumps(update(parts, cmd == 'auto', cmd == 'fill', force=(cmd == 'update'))))
    else:
        print(json.dumps({'result': 'failed', 'message': 'unknown command'}))


if __name__ == '__main__':
    main()
