#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Signature (YARA) rule management and scanning for the download protection.
#
#   signatures.py status
#   signatures.py scan FILE      rule names that match FILE (JSON), for tests
#
# Rule files come from the cloud server (cloud/server/build_feeds.py). Every
# file is test-compiled on its own, so one broken rule cannot disable the rest;
# the good ones are compiled together into one rule set that the ICAP scanner
# uses. The scanner is the `yara` command line tool, called without a shell.

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cloudlib  # noqa: E402

AV_DIR = os.path.join(cloudlib.BASE, 'av')
SRC_DIR = os.path.join(AV_DIR, 'yara', 'src')
RULES = os.path.join(AV_DIR, 'yara', 'rules.yarc')
INFO = os.path.join(AV_DIR, 'yara', 'info.json')
NAME = re.compile(r'^[A-Za-z0-9_.-]{1,80}\.yar$')
RULE_NAME = re.compile(r'^[A-Za-z0-9_]{1,128}$')


def tool(name):
    return shutil.which(name) or ('/usr/local/bin/' + name if os.path.exists('/usr/local/bin/' + name) else None)


def read_info():
    try:
        with open(INFO) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def namespace(name):
    return re.sub(r'[^A-Za-z0-9_]', '_', name[:-4])[:60]


def test_compile(yarac, path):
    with tempfile.TemporaryDirectory() as td:
        res = subprocess.run([yarac, path, os.path.join(td, 'o.yarc')], capture_output=True, text=True, timeout=120)
    if res.returncode == 0:
        return ''
    lines = (res.stderr or '').strip().splitlines()
    return (lines[-1] if lines else 'does not compile')[:160]


def compile_all():
    """test every rule file, then build the combined rule set from the good ones"""
    yarac = tool('yarac')
    if yarac is None:
        return {'ok': False, 'error': 'the yara package is not installed'}
    info = read_info()
    known = info.get('files', {})
    good, bad = [], []
    for name in sorted(os.listdir(SRC_DIR)) if os.path.isdir(SRC_DIR) else []:
        if not NAME.match(name):
            continue
        path = os.path.join(SRC_DIR, name)
        with open(path, 'rb') as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        prev = known.get(name)
        if prev and prev.get('sha256') == digest and prev.get('error') is not None:
            err = prev['error']
        else:
            err = test_compile(yarac, path)
        known[name] = {'sha256': digest, 'error': err}
        (bad if err else good).append(name)
    known = {k: v for k, v in known.items() if os.path.exists(os.path.join(SRC_DIR, k))}
    if not good:
        return {'ok': False, 'error': 'no usable rule file', 'rejected': bad}
    out = RULES + '.tmp'
    args = [yarac] + ['%s:%s' % (namespace(n), os.path.join(SRC_DIR, n)) for n in good] + [out]
    res = subprocess.run(args, capture_output=True, text=True, timeout=300)
    if res.returncode != 0:
        # a clash between files (duplicate rule names are namespaced, but modules differ): fall back to nothing new
        return {'ok': False, 'error': ((res.stderr or '').strip().splitlines() or ['compile failed'])[-1][:200]}
    os.replace(out, RULES)
    os.chmod(RULES, 0o600)
    info = {'ts': cloudlib.now(), 'files': known, 'usable': len(good), 'rejected': len(bad)}
    cloudlib.write_atomic(INFO, json.dumps(info))
    return {'ok': True, 'usable': len(good), 'rejected': len(bad)}


def update(base):
    """fetch the signature index and files from the cloud server, then compile"""
    status, raw, _etag = cloudlib.get(base + '/yara/index.json', timeout=30)
    index = json.loads(raw.decode('utf-8', 'replace'))
    wanted = {}
    for ent in index.get('files', []):
        name = str(ent.get('name', ''))
        if NAME.match(name) and re.fullmatch(r'[0-9a-f]{64}', str(ent.get('sha256', ''))):
            wanted[name] = ent['sha256']
    if not wanted:
        raise ValueError('the server offers no signature files')
    os.makedirs(SRC_DIR, exist_ok=True)
    fetched = 0
    for name, digest in wanted.items():
        path = os.path.join(SRC_DIR, name)
        if os.path.exists(path):
            with open(path, 'rb') as f:
                if hashlib.sha256(f.read()).hexdigest() == digest:
                    continue
        _s, body, _e = cloudlib.get(base + '/yara/' + name, timeout=30, limit=2 * 1024 * 1024)
        if hashlib.sha256(body).hexdigest() != digest:
            raise ValueError('checksum mismatch for ' + name)
        cloudlib.write_atomic(path, body)
        fetched += 1
    removed = 0
    for name in os.listdir(SRC_DIR):
        if name not in wanted and NAME.match(name):
            os.unlink(os.path.join(SRC_DIR, name))
            removed += 1
    res = compile_all()
    res.update(fetched=fetched, removed=removed, offered=len(wanted))
    return res


def status():
    info = read_info()
    rules = 0
    try:
        for n in os.listdir(SRC_DIR):
            with open(os.path.join(SRC_DIR, n), 'rb') as f:
                rules += len(re.findall(rb'^\s*(?:private\s+|global\s+)*rule\s+\w+', f.read(), re.M))
    except OSError:
        pass
    return {'installed': tool('yara') is not None, 'ready': os.path.exists(RULES), 'ts': info.get('ts', 0),
            'files': info.get('usable', 0), 'rejected': info.get('rejected', 0), 'rules': rules}


def scan_file(path, timeout=20):
    """names of the rules that match the file; [] when nothing matches or the scanner is unavailable"""
    yara = tool('yara')
    if yara is None or not os.path.exists(RULES):
        return []
    try:
        res = subprocess.run([yara, '-C', '-f', '-a', str(timeout), '-p', '1', RULES, path],
                             capture_output=True, text=True, timeout=timeout + 10)
    except (subprocess.SubprocessError, OSError):
        return []
    out = []
    for line in res.stdout.splitlines():
        rule = line.split(' ', 1)[0]
        rule = rule.split(':')[-1]
        if RULE_NAME.match(rule):
            out.append(rule)
    return out


def scan_bytes(data, timeout=20):
    """scan in-memory data through a private temporary file"""
    os.makedirs(os.path.join(AV_DIR, 'tmp'), mode=0o700, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix='scan.', dir=os.path.join(AV_DIR, 'tmp'))
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        return scan_file(path, timeout)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'status'
    if cmd == 'scan' and len(sys.argv) > 2:
        print(json.dumps({'matches': scan_file(sys.argv[2])}))
    else:
        print(json.dumps(status()))


if __name__ == '__main__':
    main()
