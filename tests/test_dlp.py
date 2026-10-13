#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Unit tests for the sensitive-data detectors and masking.
#   python3 -m unittest tests/test_dlp.py
#
# Secret-looking samples are assembled at runtime so no real-looking token is
# stored literally in the repository (and secret scanners stay quiet).

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'security', 'layer7security',
                                'src', 'opnsense', 'scripts', 'OPNsense', 'Layer7Security'))
import dlp_rules as d  # noqa: E402


def verhoeff_make(prefix11):
    """append a valid Verhoeff check digit"""
    for c in '0123456789':
        if d.verhoeff_ok(prefix11 + c):
            return prefix11 + c
    raise AssertionError


def cats(text, categories=d.CATEGORIES):
    return {x.category for x in d.scan(text, categories)}


def rules(text, categories=d.CATEGORIES):
    return {x.rule for x in d.scan(text, categories)}


class Checksums(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(d.luhn_ok('4111111111111111'))
        self.assertTrue(d.luhn_ok('5555555555554444'))
        self.assertFalse(d.luhn_ok('4111111111111112'))

    def test_verhoeff(self):
        self.assertTrue(d.verhoeff_ok(verhoeff_make('23456789012')))
        self.assertFalse(d.verhoeff_ok('234567890123') and d.verhoeff_ok('234567890124'))

    def test_iban(self):
        self.assertTrue(d.iban_ok('GB82 WEST 1234 5698 7654 32'))
        self.assertFalse(d.iban_ok('GB82 WEST 1234 5698 7654 33'))


class Cards(unittest.TestCase):
    def test_detects_formatted_and_plain(self):
        for text in ('card 4111 1111 1111 1111 exp', 'pay 4111-1111-1111-1111.', 'n=5555555555554444;',
                     'amex 378282246310005 ok'):
            self.assertIn('card', cats(text), text)

    def test_rejects_non_cards(self):
        for text in ('order 1234567890123456', 'id 4111111111111112', 'ts 1700000000000', 'x' * 5 + '0000000000000000'):
            self.assertNotIn('card', cats(text), text)

    def test_mask_keeps_last4_and_length(self):
        src = 'my card is 4111 1111 1111 1111 thanks'
        masked = d.mask_text(src)
        self.assertEqual(len(masked), len(src))
        self.assertNotIn('4111 1111', masked)
        self.assertIn('1111', masked.split('is')[1])
        self.assertTrue(masked.endswith('thanks'))


class Ids(unittest.TestCase):
    def test_ssn(self):
        self.assertIn('us-ssn', rules('ssn 123-45-6789'))
        self.assertNotIn('us-ssn', rules('ssn 000-45-6789 and 666-12-3456 and 123-00-6789'))

    def test_aadhaar_needs_valid_checksum(self):
        good = verhoeff_make('23456789012')
        self.assertIn('in-aadhaar', rules('aadhaar ' + good))
        self.assertIn('in-aadhaar', rules('aadhaar %s %s %s' % (good[:4], good[4:8], good[8:])))
        bad = good[:-1] + str((int(good[-1]) + 1) % 10)
        self.assertNotIn('in-aadhaar', rules('aadhaar ' + bad))

    def test_pan_iban_nino(self):
        self.assertIn('in-pan', rules('pan ABCPE1234F'))
        self.assertNotIn('in-pan', rules('code ABCDE1234F'))   # 4th letter not a holder type
        self.assertIn('iban', rules('iban GB82 WEST 1234 5698 7654 32'))
        self.assertIn('uk-nino', rules('ni AB 12 34 56 C'))


class Keys(unittest.TestCase):
    def test_provider_formats(self):
        samples = {
            'anthropic': 'sk-ant-' + 'api03-' + 'aB3dE5gH7jK9mN1pQ3sT5v',
            'aws-access-key': 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP',
            'google-api-key': 'AI' + 'za' + 'A' * 35,
            'github-token': 'gh' + 'p_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8',
            'slack-token': 'xo' + 'xb-' + '1234567890-abcdefghij',
            'stripe-key': 'sk' + '_live_' + 'aBcDeFgHiJkLmNoPqR',
            'private-key': '-----BEGIN RSA PRIVATE ' + 'KEY-----',
            'jwt': 'ey' + 'JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop',
        }
        for rule, value in samples.items():
            self.assertIn(rule, rules('here: ' + value + ' end'), rule)

    def test_openai_vs_anthropic_attribution(self):
        self.assertIn('anthropic', rules('sk-ant-' + 'x9Y8w7V6u5T4s3R2q1P0o9N8m7L6'))
        text = 'sk-' + 'proj-' + 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'
        self.assertIn('openai', rules(text))
        self.assertNotIn('anthropic', rules(text))

    def test_assignment_needs_entropy_and_not_placeholder(self):
        self.assertIn('assignment', rules('password = "Xk9$vT2#mQ7wLp4Z"'))
        self.assertIn('assignment', rules('{"api_key": "9fA3kLm2Qx7ZpR4vB8nT"}'))
        self.assertNotIn('assignment', rules('api_key = "your_api_key_here_please"'))
        self.assertNotIn('assignment', rules('password = "aaaaaaaaaaaaaaaa"'))
        self.assertNotIn('assignment', rules('token = "process.env.TOKEN_VALUE_X"'))

    def test_mask_keeps_prefix_and_last_two(self):
        key = 'sk-ant-' + 'api03-' + 'aB3dE5gH7jK9mN1pQ3sT5v'
        masked = d.mask_text('use ' + key + ' now')
        self.assertTrue(masked.startswith('use sk-ant-'))
        self.assertTrue(masked.endswith('5v now'))
        self.assertNotIn('aB3dE5', masked)
        self.assertEqual(len(masked), len('use ' + key + ' now'))


CODE = '''import os
import sys

def main(argv):
    total = 0
    for name in argv:
        if os.path.exists(name):
            total += os.path.getsize(name)
    print(total)
    return 0

class Reader:
    def __init__(self, path):
        self.path = path
'''

PROSE = ('The quick brown fox jumps over the lazy dog. ' * 3 + '\n') * 12


class Code(unittest.TestCase):
    def test_detects_source_and_language(self):
        ok, lines, lang = d.code_info(CODE)
        self.assertTrue(ok)
        self.assertEqual(lang, 'python')
        self.assertIn('code', cats(CODE))

    def test_prose_and_short_snippets_are_not_code(self):
        self.assertFalse(d.code_info(PROSE)[0])
        self.assertNotIn('code', cats('def f(x):\n    return x\n'))

    def test_code_detection_has_no_snippet(self):
        det = [x for x in d.scan(CODE) if x.category == 'code'][0]
        self.assertEqual(d.snippet(CODE, det), '')


class Extraction(unittest.TestCase):
    def test_json_strings_are_unwrapped(self):
        body = json.dumps({'messages': [{'role': 'user', 'content': 'card 4111 1111 1111 1111'}]}).encode()
        self.assertIn('card', cats(d.extract_text(body, 'application/json')))

    def test_gzip_body(self):
        import gzip
        body = gzip.compress(b'{"p":"ssn 123-45-6789"}')
        self.assertIn('id', cats(d.extract_text(body, 'application/json', 'gzip')))

    def test_unicode_escapes_cannot_hide_data(self):
        body = ('{"p": "' + ''.join('\\u%04x' % ord(c) for c in '123-45-6789') + '"}').encode()
        self.assertIn('id', cats(d.extract_text(body, 'application/json')))

    def test_garbage_does_not_raise(self):
        for body in (b'\xff\xfe\x00', b'{"a":', b'', b'[' * 5000):
            d.extract_text(body, 'application/json')


class Snippets(unittest.TestCase):
    def test_snippet_is_masked_and_short(self):
        text = 'please summarise my record: patient card 4111 1111 1111 1111 and then continue ' * 3
        det = d.scan(text, ['card'])[0]
        snip = d.snippet(text, det)
        self.assertNotIn('4111 1111 1111', snip)
        self.assertLess(len(snip), 120)
        self.assertIn('1111', snip)


if __name__ == '__main__':
    unittest.main()
