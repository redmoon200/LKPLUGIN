#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# License keys of os-layer7security: build, sign, verify. The plugin has the same
# format in PHP (License.php); only the public key is shipped with the plugin.
#
# Key layout (before base32):
#   payload (22 bytes)
#     1  version     = 1
#     1  type        1 trial (30 days) | 2 year (365 days) | 4 lifetime (never expires)
#     2  issued      days since 2020-01-01 (big endian)
#     2  duration    days (trial 30, year 365, lifetime 0)
#     8  key id      random, unique per key
#     8  binding     first 8 bytes of sha256("L7BIND1|" + install id hex), zeros = not tied to one firewall
#   signature (64 bytes) Ed25519 over "L7LIC1\0" + payload
# Text form: base32 (A-Z, 2-7) in groups of five.
#
# Ed25519 is done with the openssl command line (OpenSSL 3), no extra packages.

import base64
import hashlib
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time

EPOCH = 1577836800            # 2020-01-01 UTC
TYPES = {1: 'trial', 2: 'year', 4: 'lifetime'}
TYPE_IDS = {v: k for k, v in TYPES.items()}
DAYS = {'trial': 30, 'year': 365, 'lifetime': 0}
LABELS = {'trial': 'Trial (30 days)', 'year': 'Standard (1 year)', 'lifetime': 'Lifetime'}
PAYLOAD_LEN = 22
B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
INSTALL_ID = re.compile(r'^[0-9A-F]{4}(-[0-9A-F]{4}){3}$')
OPENSSL = os.environ.get('L7_OPENSSL') or shutil.which('openssl') or '/usr/bin/openssl'


def b32_encode(data):
    bits = ''.join(format(b, '08b') for b in data)
    return ''.join(B32[int(bits[i:i + 5].ljust(5, '0'), 2)] for i in range(0, len(bits), 5))


def b32_decode(text):
    bits = ''
    for ch in text:
        p = B32.find(ch)
        if p < 0:
            return None
        bits += format(p, '05b')
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - len(bits) % 8, 8))


def normalize(text):
    return re.sub(r'[^A-Z2-7]', '', text.upper())


def group(blob):
    t = b32_encode(blob)
    return '-'.join(t[i:i + 5] for i in range(0, len(t), 5))


def install_hex(install_id):
    return re.sub(r'[^0-9A-F]', '', install_id.upper())


def bind_hash(install_id):
    return hashlib.sha256(('L7BIND1|' + install_hex(install_id)).encode()).digest()[:8]


def valid_install_id(text):
    return bool(INSTALL_ID.match((text or '').strip().upper()))


def run(args, **kw):
    return subprocess.run(args, capture_output=True, timeout=30, **kw)


def generate_keypair(private_pem):
    """create the vendor signing key (once); returns the public key PEM"""
    os.makedirs(os.path.dirname(private_pem), mode=0o700, exist_ok=True)
    if not os.path.exists(private_pem):
        res = run([OPENSSL, 'genpkey', '-algorithm', 'ed25519', '-out', private_pem])
        if res.returncode != 0:
            raise RuntimeError('cannot create the signing key: ' + res.stderr.decode()[:200])
        os.chmod(private_pem, 0o600)
    return public_pem(private_pem)


def public_pem(private_pem):
    res = run([OPENSSL, 'pkey', '-in', private_pem, '-pubout'])
    if res.returncode != 0:
        raise RuntimeError('cannot read the signing key')
    return res.stdout.decode().replace(chr(13), '')


def public_b64(pub_pem):
    """the raw 32 byte public key, base64 (last 32 bytes of the DER form)"""
    body = ''.join(l for l in pub_pem.splitlines() if not l.startswith('-----'))
    return base64.b64encode(base64.b64decode(body)[-32:]).decode()


def build_payload(type_name, issued_ts, key_id, bind=b'\0' * 8):
    days = DAYS[type_name]
    d = (int(issued_ts) - EPOCH) // 86400
    return bytes([1, TYPE_IDS[type_name]]) + d.to_bytes(2, 'big') + days.to_bytes(2, 'big') + key_id + bind


def sign(payload, private_pem):
    with tempfile.TemporaryDirectory() as td:
        m = os.path.join(td, 'm')
        s = os.path.join(td, 's')
        with open(m, 'wb') as f:
            f.write(b'L7LIC1\0' + payload)
        res = run([OPENSSL, 'pkeyutl', '-sign', '-inkey', private_pem, '-rawin', '-in', m, '-out', s])
        if res.returncode != 0:
            raise RuntimeError('signing failed: ' + res.stderr.decode()[:200])
        with open(s, 'rb') as f:
            return payload + f.read()


def verify_signature(blob, public_pem_text):
    if len(blob) != PAYLOAD_LEN + 64:
        return False
    with tempfile.TemporaryDirectory() as td:
        m, s, p = (os.path.join(td, x) for x in ('m', 's', 'p'))
        with open(m, 'wb') as f:
            f.write(b'L7LIC1\0' + blob[:PAYLOAD_LEN])
        with open(s, 'wb') as f:
            f.write(blob[PAYLOAD_LEN:])
        with open(p, 'w', newline='') as f:
            f.write(public_pem_text)
        res = run([OPENSSL, 'pkeyutl', '-verify', '-pubin', '-inkey', p, '-rawin', '-in', m, '-sigfile', s])
        return res.returncode == 0


def issue(type_name, private_pem, install_id='', issued_ts=None, now=None):
    """a signed key; returns dict(key, key_id, type, issued, expires, bound)"""
    if type_name not in TYPE_IDS:
        raise ValueError('unknown license type')
    issued_ts = int(issued_ts if issued_ts is not None else (now or time.time()))
    key_id = secrets.token_bytes(8)
    bind = b'\0' * 8
    if install_id:
        if not valid_install_id(install_id):
            raise ValueError('the installation id looks like 1234-ABCD-5678-EF01')
        bind = bind_hash(install_id)
    blob = sign(build_payload(type_name, issued_ts, key_id, bind), private_pem)
    return describe(blob, group(blob))


def describe(blob, key_text):
    payload = blob[:PAYLOAD_LEN]
    type_name = TYPES[payload[1]]
    issued = EPOCH + int.from_bytes(payload[2:4], 'big') * 86400
    days = int.from_bytes(payload[4:6], 'big')
    return {'key': key_text, 'key_id': payload[6:14].hex().upper(), 'type': type_name, 'label': LABELS[type_name],
            'issued': issued, 'days': days, 'expires': None if type_name == 'lifetime' else issued + days * 86400,
            'bound': payload[14:22] != b'\0' * 8, 'bind': payload[14:22].hex()}


def parse(key_text, public_pem_text):
    """-> dict with ok True and the key's fields, or ok False and an error"""
    raw = b32_decode(normalize(key_text or ''))
    if raw is None or len(raw) != PAYLOAD_LEN + 64:
        return {'ok': False, 'error': 'That does not look like a license key.'}
    if not verify_signature(raw, public_pem_text):
        return {'ok': False, 'error': 'Invalid license key (signature check failed).'}
    payload = raw[:PAYLOAD_LEN]
    if payload[0] != 1 or payload[1] not in TYPES:
        return {'ok': False, 'error': 'Unsupported license key.'}
    info = describe(raw, group(raw))
    if (info['type'] == 'lifetime') != (info['days'] == 0):
        return {'ok': False, 'error': 'Invalid license duration.'}
    info['ok'] = True
    return info
