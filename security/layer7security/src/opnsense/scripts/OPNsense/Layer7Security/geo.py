#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# GeoIP data for os-layer7security.
#   geo.py update   download the country database (iptoasn.com, public domain,
#                   or <geoSource>/ip2country-v{4,6}.tsv.gz), normalise it into
#                   v4.tsv / v6.tsv for the engine, rebuild policy tables
#   geo.py auto     same, silent, only when GeoIP is enabled
#   geo.py build    rebuild the per-policy CIDR files from geo_policies.json
#   geo.py status   JSON: database info, policy tables, pf rule counters
#
# v4.tsv: "<start int> <end int> <CC>", v6.tsv: "<start hex32> <end hex32> <CC>"
# The data maps address ranges by registry allocation; it is an approximation.

import gzip
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

CONFIG = '/conf/config.xml'
GEO_DIR = '/var/db/layer7security/geo'
POLICIES = '/usr/local/etc/layer7security/geo_policies.json'
DEFAULT_BASE = 'https://iptoasn.com/data'
MAX_BYTES = 120 * 1024 * 1024

PRIVATE4 = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
            '192.168.0.0/16', '224.0.0.0/4']
PRIVATE6 = ['::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8']
CC = re.compile(r'^[A-Z]{2}$')


def read_general():
    try:
        node = ET.parse(CONFIG).getroot().find('./OPNsense/layer7security/general')
    except (OSError, ET.ParseError):
        return {}
    return {c.tag: (c.text or '') for c in node} if node is not None else {}


def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'os-layer7security'})
    with urllib.request.urlopen(req, timeout=180) as resp:
        raw = resp.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('download too large')
    return gzip.decompress(raw).decode('utf-8', 'replace') if raw[:2] == b'\x1f\x8b' else raw.decode('utf-8', 'replace')


def normalise(text, v6):
    """iptoasn lines: start<TAB>end<TAB>CC (CC 'None' = unknown); returns sorted list"""
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3 or not CC.match(parts[2].upper()) or parts[2] == 'None':
            continue
        try:
            a = ipaddress.ip_address(parts[0])
            b = ipaddress.ip_address(parts[1])
        except ValueError:
            continue
        if (a.version == 6) != v6 or int(b) < int(a):
            continue
        rows.append((int(a), int(b), parts[2].upper()))
    rows.sort()
    return rows


def write_rows(path, rows, v6):
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        for a, b, cc in rows:
            if v6:
                f.write('%032x %032x %s\n' % (a, b, cc))
            else:
                f.write('%d %d %s\n' % (a, b, cc))
    os.replace(tmp, path)


def load_rows(name, v6):
    rows = []
    try:
        with open(os.path.join(GEO_DIR, name)) as f:
            for line in f:
                a, b, cc = line.split()
                rows.append((int(a, 16) if v6 else int(a), int(b, 16) if v6 else int(b), cc))
    except OSError:
        pass
    return rows


def subtract(ranges, holes):
    """ranges, holes: sorted lists of (start, end); returns ranges minus holes"""
    out = []
    holes = sorted(holes)
    for a, b in ranges:
        cur = a
        for h0, h1 in holes:
            if h1 < cur or h0 > b:
                continue
            if h0 > cur:
                out.append((cur, h0 - 1))
            cur = max(cur, h1 + 1)
            if cur > b:
                break
        if cur <= b:
            out.append((cur, b))
    return out


def merge(ranges):
    ranges = sorted(ranges)
    out = []
    for a, b in ranges:
        if out and a <= out[-1][1] + 1:
            if b > out[-1][1]:
                out[-1] = (out[-1][0], b)
        else:
            out.append((a, b))
    return out


def to_cidrs(ranges, v6):
    cls = ipaddress.IPv6Address if v6 else ipaddress.IPv4Address
    for a, b in ranges:
        for net in ipaddress.summarize_address_range(cls(a), cls(b)):
            yield str(net)


def net_ranges(specs):
    v4, v6 = [], []
    for spec in specs:
        try:
            n = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            continue
        (v6 if n.version == 6 else v4).append((int(n.network_address), int(n.broadcast_address)))
    return merge(v4), merge(v6)


def build():
    try:
        with open(POLICIES) as f:
            policies = json.load(f)
    except (OSError, ValueError):
        policies = []
    v4 = load_rows('v4.tsv', False)
    v6 = load_rows('v6.tsv', True)
    built = []
    for p in policies:
        wanted = set(p.get('countries', []))
        r4 = merge([(a, b) for a, b, cc in v4 if cc in wanted])
        r6 = merge([(a, b) for a, b, cc in v6 if cc in wanted])
        ex4, ex6 = net_ranges(p.get('exceptions', []))
        if p.get('action') == 'allow':
            p4, p6 = net_ranges(PRIVATE4 + PRIVATE6)
            r4 = merge(r4 + p4 + ex4)
            r6 = merge(r6 + p6 + ex6)
            if not (v4 or v6):
                r4, r6 = [], []
        else:
            r4 = subtract(r4, ex4)
            r6 = subtract(r6, ex6)
        lines = list(to_cidrs(r4, False)) + list(to_cidrs(r6, True))
        path = p['file']
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + '.tmp', 'w') as f:
            f.write(''.join(l + '\n' for l in lines))
        os.replace(path + '.tmp', path)
        built.append({'id': p['id'], 'name': p['name'], 'entries': len(lines)})
    return built


def meta_path():
    return os.path.join(GEO_DIR, 'meta.json')


def update(quiet):
    general = read_general()
    if quiet and general.get('geoEnabled') != '1':
        return {'result': 'skipped'}
    base = (general.get('geoSource') or '').strip().rstrip('/') or DEFAULT_BASE
    if not re.match(r'^https?://[A-Za-z0-9.:/_-]{1,200}$', base):
        return {'result': 'failed', 'message': 'invalid source URL'}
    os.makedirs(GEO_DIR, exist_ok=True)
    try:
        r4 = normalise(fetch(base + '/ip2country-v4.tsv.gz'), False)
        r6 = normalise(fetch(base + '/ip2country-v6.tsv.gz'), True)
    except Exception as exc:
        return {'result': 'failed', 'message': str(exc)[:160]}
    if len(r4) < 1000:
        return {'result': 'failed', 'message': 'database looks incomplete (%d IPv4 ranges)' % len(r4)}
    write_rows(os.path.join(GEO_DIR, 'v4.tsv'), r4, False)
    write_rows(os.path.join(GEO_DIR, 'v6.tsv'), r6, True)
    with open(meta_path(), 'w') as f:
        json.dump({'updated': int(time.time()), 'v4_ranges': len(r4), 'v6_ranges': len(r6), 'source': base}, f)
    built = build()
    subprocess.run(['/usr/local/sbin/configctl', 'filter', 'reload'], check=False, stdout=subprocess.DEVNULL)
    return {'result': 'ok', 'v4_ranges': len(r4), 'v6_ranges': len(r6), 'tables': built}


def labels():
    out = {}
    try:
        res = subprocess.run(['/sbin/pfctl', '-s', 'labels'], capture_output=True, text=True, timeout=10)
        for line in res.stdout.splitlines():
            parts = line.split()
            if parts and parts[0].startswith('l7geo_') and len(parts) >= 5:
                out[parts[0]] = {'packets': int(parts[2]), 'bytes': int(parts[3])}
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return out


def status():
    try:
        with open(meta_path()) as f:
            meta = json.load(f)
    except (OSError, ValueError):
        meta = {}
    try:
        with open(POLICIES) as f:
            policies = json.load(f)
    except (OSError, ValueError):
        policies = []
    tables = []
    for p in policies:
        try:
            with open(p['file']) as f:
                entries = sum(1 for _ in f)
        except OSError:
            entries = 0
        tables.append({'id': p['id'], 'name': p['name'], 'entries': entries})
    return {'ready': bool(meta), 'meta': meta, 'tables': tables, 'labels': labels()}


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'status'
    if cmd == 'update':
        print(json.dumps(update(False)))
    elif cmd == 'auto':
        print(json.dumps(update(True)))
    elif cmd == 'build':
        print(json.dumps({'tables': build()}))
    elif cmd == 'status':
        print(json.dumps(status()))
    else:
        print(json.dumps({'result': 'failed', 'message': 'unknown command'}))


if __name__ == '__main__':
    main()
