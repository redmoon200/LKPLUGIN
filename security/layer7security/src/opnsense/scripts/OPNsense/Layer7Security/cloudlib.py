#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Shared helpers for everything downloaded from the cloud feed server: the
# plugin settings, conditional downloads (ETag) and the state file that the
# GUI shows as "what is installed, how many entries, how old".

import gzip
import json
import os
import re
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

CONFIG = os.environ.get('L7_CONFIG_XML', '/conf/config.xml')
BASE = os.environ.get('L7_BASE', '/var/db/layer7security')
STATE = os.path.join(BASE, 'cloud_state.json')
MAX_BYTES = 160 * 1024 * 1024
URL_OK = re.compile(r'^https?://[A-Za-z0-9.:/_-]{1,200}$')


def settings():
    """the parts of the plugin configuration the downloaders need"""
    out = {'general': {}, 'cfs': {}, 'av': {}}
    try:
        root = ET.parse(CONFIG).getroot().find('./OPNsense/layer7security')
    except (OSError, ET.ParseError):
        return out
    if root is None:
        return out
    for name in out:
        node = root.find(name)
        if node is not None:
            out[name] = {c.tag: (c.text or '') for c in node}
    return out


def base_url(cfg):
    url = (cfg['general'].get('feedUrl') or '').strip().rstrip('/')
    return url if URL_OK.match(url) else ''


def load_state():
    try:
        with open(STATE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(state):
    os.makedirs(BASE, exist_ok=True)
    tmp = STATE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(state, f)
    os.replace(tmp, STATE)


def get(url, etag=None, timeout=60, limit=MAX_BYTES):
    """-> (status, body, etag); status 304 means unchanged, body is None on errors"""
    req = urllib.request.Request(url, headers={'User-Agent': 'os-layer7security', 'Accept-Encoding': 'gzip'})
    if etag:
        req.add_header('If-None-Match', etag)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(limit + 1)
            if len(raw) > limit:
                raise ValueError('download larger than %d MB' % (limit // 1048576))
            if resp.headers.get('Content-Encoding') == 'gzip':
                raw = gzip.decompress(raw)
            return resp.status, raw, resp.headers.get('ETag')
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, None, etag
        raise


def write_atomic(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'wb' if isinstance(data, bytes) else 'w') as f:
        f.write(data)
    os.replace(tmp, path)


def count_lines(path):
    try:
        with open(path, errors='replace') as f:
            return sum(1 for line in f if line.strip() and not line.startswith('#'))
    except OSError:
        return 0


def now():
    return int(time.time())
