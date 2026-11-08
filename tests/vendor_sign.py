#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Test helper: signs what the plugin verifies (support commands and update lists) with a throw-away key, using the
# openssl command line. The vendor's real signing key and tooling are not part of this repository.

import base64
import json
import os
import shutil
import subprocess
import tempfile

OPENSSL = os.environ.get('L7_OPENSSL') or shutil.which('openssl') or '/usr/bin/openssl'
COMMAND_DOMAIN = b'L7CMD1\0'
RELEASE_DOMAIN = b'L7REL1\0'
VERSION = 1


def _run(args):
    return subprocess.run([OPENSSL] + args, capture_output=True, timeout=30)


def generate_keypair(private_pem):
    """create an Ed25519 key at private_pem; returns the public key as PEM text"""
    res = _run(['genpkey', '-algorithm', 'ed25519', '-out', private_pem])
    if res.returncode != 0:
        raise RuntimeError('openssl could not create a key: ' + res.stderr.decode()[:200])
    pub = _run(['pkey', '-in', private_pem, '-pubout'])
    return pub.stdout.decode()


def canonical(body):
    return json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def sign_message(msg, private_pem, domain):
    with tempfile.TemporaryDirectory() as td:
        m, s = os.path.join(td, 'm'), os.path.join(td, 's')
        with open(m, 'wb') as f:
            f.write(domain + msg)
        res = _run(['pkeyutl', '-sign', '-inkey', private_pem, '-rawin', '-in', m, '-out', s])
        if res.returncode != 0:
            raise RuntimeError('signing failed')
        with open(s, 'rb') as f:
            return f.read()


def command_envelope(cmd_id, fw, action, params, level, iat, exp, private_pem):
    """a signed support command as the firewall expects it"""
    body = {'v': VERSION, 'id': cmd_id, 'fw': fw, 'action': action, 'params': params, 'level': level, 'iat': iat, 'exp': exp}
    out = dict(body)
    out['sig'] = base64.b64encode(sign_message(canonical(body).encode(), private_pem, COMMAND_DOMAIN)).decode()
    return out


def sign_manifest(body, private_pem):
    return base64.b64encode(sign_message(canonical(body).encode(), private_pem, RELEASE_DOMAIN)).decode()
