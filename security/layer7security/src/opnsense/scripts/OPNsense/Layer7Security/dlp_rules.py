#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Sensitive-data detectors shared by the ICAP inspection server and the audit
# log. Every detector validates (checksum, structure, entropy) to keep false
# positives down, and masking keeps the text length so positions stay valid.
#
# Categories: card, id, api_key, code
#
#   scan(text, categories)  -> list of Detection
#   mask_text(text)         -> text with every detected value masked
#   snippet(text, det)      -> short masked context around one detection
#   extract_text(body, ctype, encoding) -> text to scan (JSON strings unwrapped)

import gzip
import json
import math
import re
import zlib
from collections import namedtuple

Detection = namedtuple('Detection', 'category rule start end')

CATEGORIES = ('card', 'id', 'api_key', 'code')

# ----------------------------------------------------------------- checksums


def luhn_ok(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


_VD = ((0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5), (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
       (3, 4, 0, 1, 2, 8, 9, 5, 6, 7), (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
       (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3), (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
       (9, 8, 7, 6, 5, 4, 3, 2, 1, 0))
_VP = ((0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4), (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
       (8, 9, 1, 6, 0, 4, 3, 5, 2, 7), (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
       (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8))


def verhoeff_ok(digits):
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VD[c][_VP[i % 8][ord(ch) - 48]]
    return c == 0


def iban_ok(value):
    value = value.replace(' ', '').upper()
    if not 15 <= len(value) <= 34 or not value[:2].isalpha() or not value[2:4].isdigit():
        return False
    rearranged = value[4:] + value[:4]
    try:
        number = ''.join(str(int(ch, 36)) for ch in rearranged)
    except ValueError:
        return False
    return int(number) % 97 == 1


def entropy(value):
    if not value:
        return 0.0
    freq = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum(n / len(value) * math.log2(n / len(value)) for n in freq.values())


# ------------------------------------------------------------------ patterns

CARD = re.compile(r'(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])')
SSN = re.compile(r'\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b')
AADHAAR = re.compile(r'(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)')
PAN = re.compile(r'\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b')
IBAN = re.compile(r'\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b')
NINO = re.compile(r'\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b')

# (rule name, regex, group holding the secret (0 = whole match))
KEYS = [
    ('anthropic', re.compile(r'\bsk-ant-[A-Za-z0-9_\-]{20,}'), 0),
    ('openai', re.compile(r'\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}'), 0),
    ('aws-access-key', re.compile(r'\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b'), 0),
    ('google-api-key', re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'), 0),
    ('github-token', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,255}\b'), 0),
    ('github-pat', re.compile(r'\bgithub_pat_[A-Za-z0-9_]{22,255}\b'), 0),
    ('slack-token', re.compile(r'\bxox[abprs]-[A-Za-z0-9-]{10,}'), 0),
    ('stripe-key', re.compile(r'\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b'), 0),
    ('private-key', re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----'), 0),
    ('jwt', re.compile(r'\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}'), 0),
    ('bearer', re.compile(r'(?i)\bbearer\s+([A-Za-z0-9._\-]{24,})'), 1),
    ('assignment', re.compile(r'''(?i)\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|token|passwd|password|pwd)\b["']?\s*[:=]\s*["']?([A-Za-z0-9_\-/+=.!@#$%^&*]{12,})'''), 1),
]
PLACEHOLDER = re.compile(r'(?i)^(?:your|my|example|sample|changeme|change_me|placeholder|xxxx|<|\$\{|\*{4}|null|none|true|false|undefined|process\.env|os\.environ)')

# source code: lines that look like code
CODE_LINE = re.compile(
    r'(?:^\s*(?:def|class|import|from\s+\S+\s+import|function|const|let|var|public|private|protected|static|'
    r'package|using|namespace|#include|#define|fn|func|impl|struct|enum|interface|return|if|else|elif|for|while|'
    r'try|catch|except|switch|case|async|await|SELECT|INSERT|UPDATE|DELETE|CREATE|@\w+)\b)'
    r'|(?:[{};]\s*$)|(?:=>|->|::|==|!=|&&|\|\|)|(?:\w+\([^)]*\)\s*[{:;]?\s*$)|(?:^\s{4,}\S.*[(){}\[\];=])')
LANGS = (('python', re.compile(r'\b(?:def |import |from \w+ import|elif |self\.|print\()')),
         ('javascript', re.compile(r'\b(?:const |let |function |=>|console\.log|require\()')),
         ('java', re.compile(r'\b(?:public (?:static )?(?:class|void)|System\.out|import java)')),
         ('c/c++', re.compile(r'(?:#include|\bint main|std::|printf\()')),
         ('go', re.compile(r'\b(?:func |package \w+|fmt\.)')),
         ('rust', re.compile(r'\b(?:fn |let mut|impl |println!)')),
         ('sql', re.compile(r'(?i)\b(?:select .+ from|insert into|create table|update .+ set)\b')),
         ('shell', re.compile(r'(?:^#!/|\bsudo |\bchmod |\|\s*grep)')))


def _scan_cards(text):
    for m in CARD.finditer(text):
        digits = re.sub(r'\D', '', m.group(0))
        if 13 <= len(digits) <= 19 and len(set(digits)) > 1 and luhn_ok(digits) and digits[0] in '23456':
            yield Detection('card', 'card-luhn', m.start(), m.end())


def _scan_ids(text):
    for m in SSN.finditer(text):
        yield Detection('id', 'us-ssn', m.start(), m.end())
    for m in AADHAAR.finditer(text):
        digits = re.sub(r'\D', '', m.group(0))
        if len(digits) == 12 and verhoeff_ok(digits) and len(set(digits)) > 3:
            yield Detection('id', 'in-aadhaar', m.start(), m.end())
    for m in PAN.finditer(text):
        yield Detection('id', 'in-pan', m.start(), m.end())
    for m in IBAN.finditer(text):
        if iban_ok(m.group(0)):
            yield Detection('id', 'iban', m.start(), m.end())
    for m in NINO.finditer(text):
        yield Detection('id', 'uk-nino', m.start(), m.end())


def _scan_keys(text):
    taken = []
    for rule, rx, grp in KEYS:
        for m in rx.finditer(text):
            s, e = m.start(grp), m.end(grp)
            if any(s < te and e > ts for ts, te in taken):
                continue
            value = m.group(grp)
            if rule in ('assignment', 'bearer'):
                if PLACEHOLDER.match(value) or entropy(value) < 3.0 or len(set(value)) < 6:
                    continue
            taken.append((s, e))
            yield Detection('api_key', rule, s, e)


def code_info(text, min_lines=8):
    """(is_code, code_lines, language) - a heuristic, tuned to avoid prose"""
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) < min_lines:
        return False, 0, ''
    code = sum(1 for l in lines if CODE_LINE.search(l))
    fenced = text.count('```') >= 2
    if code >= min_lines and (code / len(lines) >= 0.5 or (fenced and code >= min_lines)):
        lang = ''
        for name, rx in LANGS:
            if rx.search(text):
                lang = name
                break
        return True, code, lang
    return False, 0, ''


def scan(text, categories=CATEGORIES, code_min_lines=8):
    found = []
    if 'card' in categories:
        found += list(_scan_cards(text))
    if 'id' in categories:
        found += list(_scan_ids(text))
    if 'api_key' in categories:
        found += list(_scan_keys(text))
    if 'code' in categories:
        ok, lines, lang = code_info(text, code_min_lines)
        if ok:
            found.append(Detection('code', 'source-code:%s:%d' % (lang or 'unknown', lines), 0, 0))
    return sorted(found, key=lambda d: (d.start, d.end))


# ------------------------------------------------------------------- masking


def _mask_value(det, value):
    """same length as the input: digits/letters become '*', separators stay"""
    if det.category in ('card', 'id'):
        keep = 4
    elif det.rule in ('private-key',):
        keep = 0
    elif det.category == 'api_key' and det.rule not in ('assignment', 'bearer'):
        keep = 2
    else:
        keep = 0
    out = list(value)
    seen = 0
    for i in range(len(out) - 1, -1, -1):
        if out[i].isalnum() or out[i] in '_-/+=.!@#$%^&*':
            if det.category in ('card', 'id') and not out[i].isalnum():
                continue
            if seen < keep:
                seen += 1
                continue
            out[i] = '*'
    # keep a recognisable type prefix for provider keys
    if det.category == 'api_key' and det.rule in ('anthropic', 'openai', 'github-token', 'github-pat',
                                                  'slack-token', 'stripe-key', 'aws-access-key', 'google-api-key'):
        prefix = re.match(r'^(?:sk-ant-|sk-proj-|sk-svcacct-|sk-admin-|sk-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|'
                          r'xox[abprs]-|[sr]k_(?:live|test)_|AKIA|ASIA|AGPA|AIDA|AROA|ANPA|AIza)', value)
        if prefix:
            n = prefix.end()
            out[:n] = list(value[:n])
    return ''.join(out)


def mask_text(text, categories=CATEGORIES):
    """mask every detected value; code detections do not alter the text"""
    dets = [d for d in scan(text, [c for c in categories if c != 'code']) if d.end > d.start]
    if not dets:
        return text
    out, pos = [], 0
    for d in dets:
        if d.start < pos:
            continue
        out.append(text[pos:d.start])
        out.append(_mask_value(d, text[d.start:d.end]))
        pos = d.end
    out.append(text[pos:])
    return ''.join(out)


def snippet(text, det, width=36):
    """masked context around a detection (never returns raw sensitive data)"""
    if det.category == 'code' or det.end <= det.start:
        return ''
    masked = mask_text(text)
    a = max(0, det.start - width)
    b = min(len(masked), det.end + width)
    piece = re.sub(r'\s+', ' ', masked[a:b]).strip()
    return ('...' if a > 0 else '') + piece + ('...' if b < len(masked) else '')


# ----------------------------------------------------------- body extraction


def _walk(node, out, depth=0):
    if depth > 40:
        return
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            _walk(v, out, depth + 1)
    elif isinstance(node, (list, tuple)):
        for v in node:
            _walk(v, out, depth + 1)


def decode_body(body, encoding=''):
    enc = (encoding or '').lower()
    try:
        if 'gzip' in enc:
            return gzip.decompress(body)
        if 'deflate' in enc:
            return zlib.decompress(body)
    except (OSError, zlib.error, EOFError):
        return body
    return body


def extract_text(body, ctype='', encoding='', limit=4 * 1024 * 1024):
    """text of a request body: JSON string values are unwrapped (so escapes and
    nesting do not hide data), anything else is decoded as UTF-8"""
    body = decode_body(body, encoding)[:limit]
    text = body.decode('utf-8', 'replace')
    if 'json' in (ctype or '').lower() or text.lstrip()[:1] in '{[':
        try:
            parts = []
            _walk(json.loads(text), parts)
            return chr(10).join(parts) if parts else text
        except (ValueError, RecursionError):
            pass
    return text
