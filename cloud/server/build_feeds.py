#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Build per-category domain lists for the os-layer7security DNS filter from
# public blocklists. One text file per category, one domain per line.
#
#   build_feeds.py [--out DIR] [--max N]

import argparse
import json
import os
import re
import sys
import time
import urllib.request

SOURCES = {
    # category: list of (label, url)
    'ads': [('anudeepND adservers', 'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt')],
    'trackers': [('StevenBlack unified hosts (ads, trackers, malware)',
                  'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts')],
    'malware': [('abuse.ch URLhaus hostfile', 'https://urlhaus.abuse.ch/downloads/hostfile/')],
    'phishing': [('Phishing.Database active domains',
                  'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt')],
    'adult': [('StevenBlack porn-only hosts',
               'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts')],
    'gambling': [('StevenBlack gambling-only hosts',
                  'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts')],
    'social': [('StevenBlack social-only hosts',
                'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts')],
}
DOMAIN = re.compile(r'^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$')
SKIP = {'localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost', 'ip6-loopback',
        'ip6-localnet', 'ip6-mcastprefix', 'ip6-allnodes', 'ip6-allrouters', 'ip6-allhosts', '0.0.0.0'}


def parse(text):
    """plain domain lists or hosts files ("0.0.0.0 domain")"""
    out = set()
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip().lower()
        if not line:
            continue
        parts = line.split()
        name = parts[-1]
        if len(parts) > 2 or (len(parts) == 2 and parts[0] not in ('0.0.0.0', '127.0.0.1', '::', '::1')):
            continue
        if name in SKIP or not DOMAIN.match(name) or '.' not in name:
            continue
        out.add(name)
    return out


def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'l7cloud-feed-builder'})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read(64 * 1024 * 1024).decode('utf-8', 'replace')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='/var/lib/l7cloud/feeds')
    ap.add_argument('--max', type=int, default=200000, help='max domains per category')
    ap.add_argument('--data', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data'),
                    help='directory with curated lists for categories without a public source')
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    manifest = {'built': int(time.time()), 'categories': {}}
    failed = 0
    for cat, sources in SOURCES.items():
        domains = set()
        used = []
        for label, url in sources:
            try:
                got = parse(fetch(url))
                domains |= got
                used.append({'source': label, 'url': url, 'domains': len(got)})
            except Exception as exc:
                failed += 1
                used.append({'source': label, 'url': url, 'error': str(exc)[:100]})
        if not domains:
            continue
        chosen = sorted(domains)[:args.max]
        write(os.path.join(args.out, cat + '.txt'), chosen)
        manifest['categories'][cat] = {'domains': len(chosen), 'sources': used}
    # curated lists shipped with the project
    if os.path.isdir(args.data):
        for name in sorted(os.listdir(args.data)):
            if not name.endswith('.txt'):
                continue
            cat = name[:-4]
            with open(os.path.join(args.data, name)) as f:
                chosen = sorted(parse(f.read()))
            if chosen and cat not in manifest['categories']:
                write(os.path.join(args.out, name), chosen)
                manifest['categories'][cat] = {'domains': len(chosen), 'sources': [{'source': 'curated'}]}
    with open(os.path.join(args.out, 'manifest.json.tmp'), 'w') as f:
        json.dump(manifest, f, indent=1)
    os.replace(os.path.join(args.out, 'manifest.json.tmp'), os.path.join(args.out, 'manifest.json'))
    print(json.dumps({'categories': {k: v['domains'] for k, v in manifest['categories'].items()}, 'failed_sources': failed}))
    return 0 if manifest['categories'] else 1


def write(path, domains):
    with open(path + '.tmp', 'w') as f:
        f.write(''.join(d + '\n' for d in domains))
    os.replace(path + '.tmp', path)


if __name__ == '__main__':
    sys.exit(main())
