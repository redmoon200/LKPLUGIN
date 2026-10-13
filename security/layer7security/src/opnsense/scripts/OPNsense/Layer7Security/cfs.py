#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Content filtering helpers.
#
#   cfs.py lookup DOMAIN          which web categories list a domain (JSON)
#   cfs.py log MODULE MINUTES N   DNS lookups the filter answered itself: MODULE is cfs, web or all
#
# The log is read from the Unbound log (the filter include sets log-local-actions).

import datetime
import json
import os
import re
import sys
import time

BASE = os.environ.get('L7_BASE', '/var/db/layer7security')
LIST_DIR = os.path.join(BASE, 'lists')
SEED_DIR = os.environ.get('L7_SEED_DIR', '/usr/local/share/layer7security/seeds')
RESOLVER_LOG = os.environ.get('L7_RESOLVER_LOG', '/var/log/resolver/latest.log')
POLICIES = os.environ.get('L7_POLICIES', '/usr/local/etc/layer7security/policies.conf')
CATEGORIES = ['ads', 'trackers', 'malware', 'phishing', 'adult', 'gambling', 'social', 'streaming', 'games', 'botnet']
DOMAIN = re.compile(r'^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$')
LINE = re.compile(r'^<\d+>\d (\S+) \S+ unbound \S+ - \[[^\]]*\] \[[^\]]*\] info: (\S+?)\.? '
                  r'(always_nxdomain|always_refuse|redirect|always_null|refuse|deny|always_transparent) '
                  r'(\S+?)@\d+ (\S+?)\.? (\w+) IN\s*$')


def parents(name):
    """name and its parent domains: a.b.c -> a.b.c, b.c, c"""
    parts = name.split('.')
    return ['.'.join(parts[i:]) for i in range(len(parts))]


def lookup(domain):
    domain = domain.strip().lower().rstrip('.')
    domain = re.sub(r'^[a-z][a-z0-9+.-]*://', '', domain)
    domain = re.sub(r'[/?#:].*$', '', domain)
    if not DOMAIN.match(domain) or '.' not in domain:
        return {'query': domain, 'error': 'not a website name'}
    wanted = set(parents(domain)[:-1] or [domain])
    matches = []
    for cat in CATEGORIES:
        for kind, folder in (('feed', LIST_DIR), ('built-in', SEED_DIR)):
            path = os.path.join(folder, cat + '.txt')
            try:
                with open(path, errors='replace') as f:
                    for line in f:
                        entry = line.strip().lower()
                        if entry in wanted:
                            matches.append({'category': cat, 'entry': entry, 'list': kind})
                            break
            except OSError:
                continue
    return {'query': domain, 'matches': matches}


def zones_of(module):
    """zone names that belong to Web Control rules, read from the compiled policies"""
    zones = set()
    try:
        with open(POLICIES) as f:
            for line in f:
                p = line.rstrip('\n').split('\t')
                if len(p) >= 7 and p[1].startswith('Web Control') and p[6] != '-':
                    for h in p[6].split(','):
                        z = re.sub(r'^\*\.?', '', h)
                        if z:
                            zones.add(z)
    except OSError:
        pass
    return zones


def read_tail(path, size=3 * 1024 * 1024):
    try:
        with open(path, 'rb') as f:
            f.seek(0, 2)
            end = f.tell()
            f.seek(max(0, end - size))
            return f.read().decode('utf-8', 'replace').splitlines()
    except OSError:
        return []


def parse_time(text):
    try:
        return int(datetime.datetime.fromisoformat(text).timestamp())
    except ValueError:
        return 0


def dns_log(module, minutes, limit):
    web = zones_of('web')
    since = time.time() - minutes * 60
    rows, wanted_zones = [], set()
    for line in reversed(read_tail(RESOLVER_LOG)):
        m = LINE.match(line)
        if not m:
            continue
        ts = parse_time(m.group(1))
        if ts and ts < since:
            break
        zone, action, client, qname, qtype = m.group(2).lower(), m.group(3), m.group(4), m.group(5).lower(), m.group(6)
        if action in ('always_transparent',):
            continue
        rows.append({'ts': ts, 'client': client, 'zone': zone, 'query': qname, 'type': qtype, 'action': action,
                     'module': 'web' if zone in web else ''})
        wanted_zones.add(zone)
        if len(rows) >= limit * 3:
            break
    # zones that are not Web Control rules come from the category lists
    unknown = {r['zone'] for r in rows if not r['module']}
    cats = {}
    if unknown:
        for cat in CATEGORIES:
            for folder in (LIST_DIR, SEED_DIR):
                try:
                    with open(os.path.join(folder, cat + '.txt'), errors='replace') as f:
                        for entry in f:
                            e = entry.strip().lower()
                            if e in unknown and e not in cats:
                                cats[e] = cat
                except OSError:
                    continue
    out = []
    for r in rows:
        if not r['module']:
            r['module'] = 'cfs'
            r['category'] = cats.get(r['zone'], 'custom list' if r['action'] != 'redirect' else 'safe search')
        else:
            r['category'] = ''
        if module in ('all', r['module']):
            out.append(r)
        if len(out) >= limit:
            break
    return {'rows': out}


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'lookup' and len(sys.argv) > 2:
        out = lookup(sys.argv[2])
    elif cmd == 'log':
        module = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] in ('cfs', 'web', 'all') else 'all'
        minutes = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3].isdigit() else 1440
        limit = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4].isdigit() else 200
        out = dns_log(module, max(1, min(minutes, 10080)), max(1, min(limit, 500)))
    else:
        out = {'error': 'usage: cfs.py lookup DOMAIN | log MODULE MINUTES N'}
    print(json.dumps(out))


if __name__ == '__main__':
    main()
