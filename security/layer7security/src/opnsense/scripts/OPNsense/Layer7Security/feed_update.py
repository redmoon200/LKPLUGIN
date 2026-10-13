#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# DNS category list feed.
#   feed_update.py update   download <feedUrl>/<category>.txt for every category
#   feed_update.py auto     same, but silent and only when a feed is configured
#   feed_update.py status   list sizes of seed and downloaded lists
# Prints JSON. Rebuilds the Unbound filter when any list changed.

import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

CONFIG = '/conf/config.xml'
LIST_DIR = '/var/db/layer7security/lists'
SEED_DIR = '/usr/local/share/layer7security/seeds'
CATEGORIES = ['ads', 'trackers', 'malware', 'phishing', 'adult', 'gambling', 'social', 'streaming', 'games']
DOMAIN = re.compile(r'^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$')
MAX_BYTES = 40 * 1024 * 1024


def read_general():
    try:
        node = ET.parse(CONFIG).getroot().find('./OPNsense/layer7security/general')
    except (OSError, ET.ParseError):
        return {}
    if node is None:
        return {}
    return {child.tag: (child.text or '') for child in node}


def count_lines(path):
    try:
        with open(path) as f:
            return sum(1 for line in f if line.strip() and not line.startswith('#'))
    except OSError:
        return 0


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


def status():
    out = []
    for cat in CATEGORIES:
        lst = os.path.join(LIST_DIR, cat + '.txt')
        out.append({
            'category': cat,
            'seed': count_lines(os.path.join(SEED_DIR, cat + '.txt')),
            'feed': count_lines(lst),
            'updated': int(os.path.getmtime(lst)) if os.path.exists(lst) else 0,
        })
    return {'lists': out}


def update(quiet):
    general = read_general()
    base = (general.get('feedUrl') or '').strip().rstrip('/')
    if not base:
        return {'result': 'skipped', 'message': 'no feed URL configured'} if not quiet else {'result': 'skipped'}
    if not re.match(r'^https?://[A-Za-z0-9.:/_-]{1,200}$', base):
        return {'result': 'failed', 'message': 'invalid feed URL'}
    os.makedirs(LIST_DIR, exist_ok=True)
    changed = False
    results = []
    for cat in CATEGORIES:
        item = {'category': cat}
        try:
            req = urllib.request.Request('%s/%s.txt' % (base, cat), headers={'User-Agent': 'os-layer7security'})
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError('list too large')
            domains = parse_list(raw.decode('utf-8', 'replace'))
            body = ''.join(d + '\n' for d in sorted(domains))
            path = os.path.join(LIST_DIR, cat + '.txt')
            old = open(path).read() if os.path.exists(path) else None
            if old != body:
                with open(path + '.tmp', 'w') as f:
                    f.write(body)
                os.replace(path + '.tmp', path)
                changed = True
            item.update({'ok': True, 'domains': len(domains)})
        except Exception as exc:  # network and parse errors are reported per list
            item.update({'ok': False, 'error': str(exc)[:120]})
        results.append(item)
    if changed and general.get('dnsFilter') == '1':
        subprocess.run(['/usr/local/opnsense/scripts/OPNsense/Layer7Security/apply.php', '--dns-only'],
                       check=False, stdout=subprocess.DEVNULL)
    ok = sum(1 for r in results if r.get('ok'))
    return {'result': 'ok' if ok else 'failed', 'updated': ok, 'total': len(results), 'lists': results,
            'ts': int(time.time())}


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'status'
    if cmd == 'status':
        print(json.dumps(status()))
    elif cmd in ('update', 'auto'):
        print(json.dumps(update(cmd == 'auto')))
    else:
        print(json.dumps({'result': 'failed', 'message': 'unknown command'}))


if __name__ == '__main__':
    main()
