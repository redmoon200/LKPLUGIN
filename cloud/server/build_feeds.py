#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Builds everything the os-layer7security plugin downloads from the cloud
# server, from public sources:
#
#   <category>.txt          domain lists per web category (ads, malware, phishing, botnet ...)
#   ip/<id>.txt             IP threat lists (botnet C2, compromised, attackers, hijacked networks, Tor)
#   hashes/<algo>.txt       known malware file hashes: "hash;family" per line (sha256, sha1, md5)
#   yara/index.json         signature files (YARA) with checksums, plus the .yar files
#   ip2country-v4/v6.tsv.gz GeoIP database mirror
#   manifest.json           what was built, from which sources, under which terms
#
#   build_feeds.py [--out DIR] [--max N] [--virusshare N] [--no-community-yara] [--only parts]
#
# A source that cannot be reached never empties an existing list: the previous
# file stays in place and the manifest says so.

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

UA = {'User-Agent': 'l7cloud-feed-builder/0.2'}

DOMAIN_SOURCES = {
    # category: list of (label, url, licence)
    'ads': [('anudeepND adservers', 'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt', 'MIT')],
    'trackers': [('StevenBlack unified hosts', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'MIT')],
    'malware': [('abuse.ch URLhaus hostfile', 'https://urlhaus.abuse.ch/downloads/hostfile/', 'CC0')],
    'phishing': [('Phishing.Database active domains',
                  'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt', 'MIT')],
    'adult': [('StevenBlack porn-only hosts',
               'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts', 'MIT')],
    'gambling': [('StevenBlack gambling-only hosts',
                  'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts', 'MIT')],
    'social': [('StevenBlack social-only hosts',
                'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts', 'MIT')],
}
THREATFOX = ('abuse.ch ThreatFox', 'https://threatfox.abuse.ch/export/csv/recent/', 'CC0')
IP_SOURCES = {
    'c2': [('abuse.ch Feodo Tracker', 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 'CC0')],
    'compromised': [('Emerging Threats compromised IPs', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'BSD')],
    'attackers': [('CINS Army list', 'https://cinsscore.com/list/ci-badguys.txt', 'free to use'),
                  ('blocklist.de all attackers', 'https://lists.blocklist.de/lists/all.txt', 'free to use')],
    'drop': [('Spamhaus DROP', 'https://www.spamhaus.org/drop/drop.txt', 'free for non-commercial use')],
    'tor': [('Tor Project bulk exit list', 'https://check.torproject.org/torbulkexitlist', 'public')],
}
BAZAAR = ('abuse.ch MalwareBazaar recent hashes', 'https://bazaar.abuse.ch/export/txt/sha256/recent/', 'CC0')
VIRUSSHARE = 'https://virusshare.com/hashfiles/VirusShare_%05d.md5'
RL_RULES = ('ReversingLabs open source YARA rules',
            'https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip', 'MIT')

DOMAIN = re.compile(r'^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$')
IPV4 = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:/(\d{1,2}))?$')
SKIP = {'localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost', 'ip6-loopback',
        'ip6-localnet', 'ip6-mcastprefix', 'ip6-allnodes', 'ip6-allrouters', 'ip6-allhosts', '0.0.0.0'}


def fetch(url, limit=96 * 1024 * 1024, timeout=90):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(limit)


def fetch_text(url, **kw):
    return fetch(url, **kw).decode('utf-8', 'replace')


def parse_domains(text):
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


def valid_net(token):
    """public IPv4 address or network in canonical form; None otherwise"""
    m = IPV4.match(token)
    if not m:
        return None
    octets = [int(x) for x in m.groups()[:4]]
    bits = m.group(5)
    if any(o > 255 for o in octets) or (bits is not None and not 8 <= int(bits) <= 32):
        return None
    a, b = octets[0], octets[1]
    if a in (0, 10, 127) or a >= 224 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254):
        return None      # never ship private or special ranges: a list must not cut off the LAN
    if a == 100 and 64 <= b <= 127:
        return None
    return '.'.join(str(o) for o in octets) + ('/' + bits if bits and bits != '32' else '')


def parse_ips(text):
    out = set()
    for line in text.splitlines():
        line = re.split(r'[#;]', line, 1)[0].strip()
        if not line:
            continue
        net = valid_net(line.split()[0].split(',')[0])
        if net:
            out.add(net)
    return out


def threatfox_rows(text):
    """(ioc_type, value, threat_type, malware) rows of the ThreatFox CSV export"""
    out = []
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        f = [x.strip().strip('"') for x in line.split('", "')]
        if len(f) < 8:
            continue
        out.append((f[3], f[2], f[4], f[7]))
    return out


def write_atomic(path, data, mode='w'):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + '.tmp', mode) as f:
        f.write(data)
    os.replace(path + '.tmp', path)


def read_lines(path):
    try:
        with open(path) as f:
            return [x.rstrip('\n') for x in f]
    except OSError:
        return []


# ------------------------------------------------------------------ builders


def build_domains(out, args, manifest, tfox):
    cats = {}
    for cat, sources in DOMAIN_SOURCES.items():
        domains, used = set(), []
        for label, url, lic in sources:
            try:
                got = parse_domains(fetch_text(url))
                domains |= got
                used.append({'source': label, 'url': url, 'licence': lic, 'domains': len(got)})
            except Exception as exc:
                used.append({'source': label, 'url': url, 'licence': lic, 'error': str(exc)[:100]})
        cats[cat] = (domains, used)
    # ThreatFox: command-and-control and payload delivery domains
    if tfox:
        botnet, payload = set(), set()
        for ioc_type, value, threat, _name in tfox:
            host = None
            if ioc_type == 'domain':
                host = value.lower().rstrip('.')
            elif ioc_type == 'url':
                m = re.match(r'^https?://([^/:?#]+)', value.lower())
                host = m.group(1) if m else None
            if host and DOMAIN.match(host) and '.' in host and not IPV4.match(host):
                (botnet if threat == 'botnet_cc' else payload).add(host)

        def info(n):
            return [{'source': THREATFOX[0], 'url': THREATFOX[1], 'licence': THREATFOX[2], 'domains': n}]
        cats['botnet'] = (botnet, info(len(botnet)))
        cats['malware'] = (cats['malware'][0] | payload, cats['malware'][1] + info(len(payload)))
    for cat, (domains, used) in cats.items():
        path = os.path.join(out, cat + '.txt')
        if not domains:
            if os.path.exists(path):
                used.append({'note': 'no data this time, previous list kept'})
            manifest['categories'][cat] = {'domains': len(read_lines(path)), 'sources': used}
            continue
        chosen = sorted(domains)[:args.max]
        write_atomic(path, ''.join(d + '\n' for d in chosen))
        manifest['categories'][cat] = {'domains': len(chosen), 'sources': used}


def build_ips(out, manifest, tfox):
    for lid, sources in IP_SOURCES.items():
        nets, used = set(), []
        for label, url, lic in sources:
            try:
                got = parse_ips(fetch_text(url))
                nets |= got
                used.append({'source': label, 'url': url, 'licence': lic, 'entries': len(got)})
            except Exception as exc:
                used.append({'source': label, 'url': url, 'licence': lic, 'error': str(exc)[:100]})
        if lid == 'c2' and tfox:
            got = set()
            for ioc_type, value, threat, _name in tfox:
                if ioc_type == 'ip:port' and threat == 'botnet_cc':
                    net = valid_net(value.rsplit(':', 1)[0])
                    if net:
                        got.add(net)
            nets |= got
            used.append({'source': THREATFOX[0], 'url': THREATFOX[1], 'licence': THREATFOX[2], 'entries': len(got)})
        path = os.path.join(out, 'ip', lid + '.txt')
        if nets:
            write_atomic(path, ''.join(n + '\n' for n in sorted(nets)))
        elif os.path.exists(path):
            used.append({'note': 'no data this time, previous list kept'})
        manifest['ip'][lid] = {'entries': len(read_lines(path)), 'sources': used}


def build_hashes(out, args, manifest, tfox):
    found = {'sha256': {}, 'sha1': {}, 'md5': {}}
    width = {'sha256': 64, 'sha1': 40, 'md5': 32}
    used = []
    try:
        n = 0
        for line in fetch_text(BAZAAR[1]).splitlines():
            h = line.strip().lower()
            if re.fullmatch(r'[0-9a-f]{64}', h):
                found['sha256'].setdefault(h, '')
                n += 1
        used.append({'source': BAZAAR[0], 'url': BAZAAR[1], 'licence': BAZAAR[2], 'hashes': n})
    except Exception as exc:
        used.append({'source': BAZAAR[0], 'url': BAZAAR[1], 'licence': BAZAAR[2], 'error': str(exc)[:100]})
    if tfox:
        n = 0
        for ioc_type, value, _threat, name in tfox:
            algo = {'sha256_hash': 'sha256', 'sha1_hash': 'sha1', 'md5_hash': 'md5'}.get(ioc_type)
            v = value.strip().lower()
            if algo and re.fullmatch(r'[0-9a-f]{%d}' % width[algo], v):
                fam = re.sub(r'[^A-Za-z0-9_. -]', '', name)[:40] if name and name != 'None' else ''
                found[algo][v] = fam or found[algo].get(v, '')
                n += 1
        used.append({'source': THREATFOX[0], 'url': THREATFOX[1], 'licence': THREATFOX[2], 'hashes': n})
    if args.virusshare > 0:
        # the newest VirusShare lists: walk up from a known number to the last one that exists
        last, probe = 480, 480
        while probe < 900:
            try:
                req = urllib.request.Request(VIRUSSHARE % probe, headers=UA, method='HEAD')
                urllib.request.urlopen(req, timeout=20).close()
                last = probe
                probe += 1
            except Exception:
                break
        n = 0
        for num in range(max(0, last - args.virusshare + 1), last + 1):
            try:
                for line in fetch_text(VIRUSSHARE % num, limit=40 * 1024 * 1024, timeout=120).splitlines():
                    h = line.strip().lower()
                    if re.fullmatch(r'[0-9a-f]{32}', h):
                        found['md5'].setdefault(h, '')
                        n += 1
            except Exception as exc:
                used.append({'source': 'VirusShare %05d' % num, 'error': str(exc)[:80]})
        used.append({'source': 'VirusShare.com hash lists (latest %d)' % args.virusshare, 'url': 'https://virusshare.com/hashes',
                     'licence': 'free to use', 'hashes': n})
    totals = {}
    for algo, table in found.items():
        path = os.path.join(out, 'hashes', algo + '.txt')
        if table:
            write_atomic(path, ''.join('%s;%s\n' % (h, table[h]) if table[h] else h + '\n' for h in sorted(table)))
        totals[algo] = len(read_lines(path))
    manifest['hashes'] = {'counts': totals, 'sources': used}


def build_yara(out, args, manifest):
    yarac = shutil.which('yarac')
    own_dir = os.path.join(args.data, 'yara')
    files = {}      # published name -> (bytes, source, licence)
    if os.path.isdir(own_dir):
        for name in sorted(os.listdir(own_dir)):
            if name.endswith('.yar'):
                with open(os.path.join(own_dir, name), 'rb') as f:
                    files['l7_' + name] = (f.read(), 'os-layer7security', 'BSD-2-Clause')
    used = [{'source': 'os-layer7security own rules', 'files': len(files), 'licence': 'BSD-2-Clause'}]
    if not args.no_community_yara:
        try:
            z = zipfile.ZipFile(io.BytesIO(fetch(RL_RULES[1], limit=64 * 1024 * 1024)))
            n = 0
            for info in z.infolist():
                if re.search(r'/yara/.+\.(yara|yar)$', info.filename) and info.file_size < 400000:
                    base = re.sub(r'[^A-Za-z0-9._-]', '_', 'rl_' + os.path.basename(info.filename))
                    base = re.sub(r'\.yara$', '.yar', base)
                    files[base] = (z.read(info), RL_RULES[0], RL_RULES[2])
                    n += 1
            used.append({'source': RL_RULES[0], 'url': RL_RULES[1], 'licence': RL_RULES[2], 'files': n})
        except Exception as exc:
            used.append({'source': RL_RULES[0], 'url': RL_RULES[1], 'licence': RL_RULES[2], 'error': str(exc)[:100]})
    index, rejected = [], []
    ydir = os.path.join(out, 'yara')
    os.makedirs(ydir, exist_ok=True)
    keep = set()
    for name, (data, src, lic) in sorted(files.items()):
        if yarac:
            with tempfile.TemporaryDirectory() as td:
                p = os.path.join(td, name)
                with open(p, 'wb') as f:
                    f.write(data)
                res = subprocess.run([yarac, p, os.path.join(td, 'o.yarc')], capture_output=True, text=True, timeout=120)
                if res.returncode != 0:
                    lines = (res.stderr or '').strip().splitlines()
                    rejected.append({'file': name, 'error': (lines[-1] if lines else 'error')[:160]})
                    continue
        with open(os.path.join(ydir, name), 'wb') as f:
            f.write(data)
        keep.add(name)
        index.append({'name': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'source': src,
                      'licence': lic, 'rules': len(re.findall(rb'^\s*(?:private\s+|global\s+)*rule\s+\w+', data, re.M))})
    for old in os.listdir(ydir):
        if old.endswith('.yar') and old not in keep:
            os.unlink(os.path.join(ydir, old))
    if index:
        write_atomic(os.path.join(ydir, 'index.json'), json.dumps({'built': int(time.time()), 'files': index}, indent=1))
    manifest['yara'] = {'files': len(index), 'rules': sum(i['rules'] for i in index), 'rejected': rejected[:30],
                        'checked_with': 'yarac' if yarac else 'not checked (yarac missing)', 'sources': used}


def build_geoip(out, manifest):
    # GeoIP country database mirror (public domain, iptoasn.com): served as-is
    for name in ('ip2country-v4.tsv.gz', 'ip2country-v6.tsv.gz'):
        try:
            raw = fetch('https://iptoasn.com/data/' + name, limit=64 * 1024 * 1024, timeout=120)
            if len(raw) > 100000 and raw[:2] == bytes([0x1f, 0x8b]):
                write_atomic(os.path.join(out, name), raw, 'wb')
                manifest.setdefault('geoip', {})[name] = len(raw)
        except Exception as exc:
            manifest.setdefault('geoip_errors', []).append('%s: %s' % (name, str(exc)[:80]))


def build_curated(out, args, manifest):
    """curated lists shipped with the project for categories without a public source"""
    if not os.path.isdir(args.data):
        return
    for name in sorted(os.listdir(args.data)):
        if not name.endswith('.txt'):
            continue
        cat = name[:-4]
        with open(os.path.join(args.data, name)) as f:
            chosen = sorted(parse_domains(f.read()))
        if chosen and cat not in manifest['categories']:
            write_atomic(os.path.join(out, name), ''.join(d + '\n' for d in chosen))
            manifest['categories'][cat] = {'domains': len(chosen), 'sources': [{'source': 'curated'}]}


def source_errors(manifest):
    """every source that failed, for the dashboard"""
    out = []

    def walk(node, where):
        if isinstance(node, dict):
            if 'error' in node:
                out.append({'where': where, 'source': node.get('source', ''), 'error': node['error']})
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    walk(v, where if k == 'sources' else (where + '/' + k if where else k))
        elif isinstance(node, list):
            for v in node:
                walk(v, where)
    walk({k: manifest.get(k) for k in ('categories', 'ip', 'hashes', 'yara') if manifest.get(k)}, '')
    return out[:60]


def record_status(root, entry):
    path = os.path.join(root, 'build_status.json')
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    hist = [entry] + data.get('history', [])
    write_atomic(path, json.dumps({'history': hist[:30]}))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='/var/lib/l7cloud/feeds')
    ap.add_argument('--max', type=int, default=200000, help='max domains per category')
    ap.add_argument('--data', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data'),
                    help='directory with curated lists and own YARA rules')
    ap.add_argument('--virusshare', type=int, default=3,
                    help='how many of the newest VirusShare MD5 lists to include (0 = none)')
    ap.add_argument('--no-community-yara', action='store_true', help="only ship the project's own YARA rules")
    ap.add_argument('--only', default='', help='comma list of parts: domains,ips,hashes,yara,geoip (default all)')
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    state_dir = os.path.dirname(os.path.abspath(args.out.rstrip('/')))
    lock = os.path.join(state_dir, 'build.lock')
    try:
        with open(lock) as f:
            os.kill(int(f.read().strip() or 0), 0)
        print('another build is running', file=sys.stderr)
        return 3
    except (OSError, ValueError):
        pass
    with open(lock, 'w') as f:
        f.write(str(os.getpid()))
    started = time.time()
    try:
        rc = build(args)
    except Exception as exc:
        record_status(state_dir, {'ts': int(started), 'seconds': int(time.time() - started), 'ok': False,
                                  'errors': [{'where': 'build', 'source': '', 'error': str(exc)[:200]}], 'counts': {}})
        raise
    finally:
        try:
            os.unlink(lock)
        except OSError:
            pass
    return rc


def build(args):
    started = time.time()
    state_dir = os.path.dirname(os.path.abspath(args.out.rstrip('/')))
    only = {x for x in args.only.split(',') if x} or {'domains', 'ips', 'hashes', 'yara', 'geoip'}
    old = {}
    try:
        with open(os.path.join(args.out, 'manifest.json')) as f:
            old = json.load(f)
    except (OSError, ValueError):
        pass
    manifest = {'built': int(time.time()), 'version': 2, 'categories': {}, 'ip': {}, 'hashes': {}, 'yara': {}}
    tfox = None
    if only & {'domains', 'ips', 'hashes'}:
        try:
            tfox = threatfox_rows(fetch_text(THREATFOX[1]))
        except Exception as exc:
            print('ThreatFox: %s' % exc, file=sys.stderr)
    if 'domains' in only:
        build_domains(args.out, args, manifest, tfox)
        build_curated(args.out, args, manifest)
    else:
        manifest['categories'] = old.get('categories', {})
    if 'ips' in only:
        build_ips(args.out, manifest, tfox)
    else:
        manifest['ip'] = old.get('ip', {})
    if 'hashes' in only:
        build_hashes(args.out, args, manifest, tfox)
    else:
        manifest['hashes'] = old.get('hashes', {})
    if 'yara' in only:
        build_yara(args.out, args, manifest)
    else:
        manifest['yara'] = old.get('yara', {})
    if 'geoip' in only:
        build_geoip(args.out, manifest)
    elif 'geoip' in old:
        manifest['geoip'] = old['geoip']
    write_atomic(os.path.join(args.out, 'manifest.json'), json.dumps(manifest, indent=1))
    counts = {'categories': {k: v['domains'] for k, v in manifest['categories'].items()},
              'ip': {k: v['entries'] for k, v in manifest['ip'].items()},
              'hashes': manifest['hashes'].get('counts'),
              'yara': {k: manifest['yara'].get(k) for k in ('files', 'rules')}}
    errors = source_errors(manifest)
    record_status(state_dir, {'ts': int(started), 'seconds': int(time.time() - started), 'ok': bool(manifest['categories']),
                              'parts': sorted(only), 'errors': errors, 'counts': counts})
    print(json.dumps(counts))
    return 0 if manifest['categories'] else 1


if __name__ == '__main__':
    sys.exit(main())
