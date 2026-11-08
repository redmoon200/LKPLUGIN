#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Unit tests for the plugin's list downloader, the web control / CFS lookup helpers and the resolver log parser.
#   python -m unittest tests/test_cloud.py

import os
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
SCRIPTS = os.path.join(ROOT, 'security', 'layer7security', 'src', 'opnsense', 'scripts', 'OPNsense', 'Layer7Security')
sys.path.insert(0, SCRIPTS)

import cfs  # noqa: E402
import feed_update as fu  # noqa: E402


class DownloaderTest(unittest.TestCase):
    def test_hash_lines_with_family_names(self):
        md5 = 'a' * 32
        text = '# c\n%s;Mirai\n%s\nzz\n%s;bad name$$\n' % (md5, 'B' * 32, 'c' * 32)
        got = fu.parse_hashes(text, 32)
        self.assertEqual(got, [md5 + ';Mirai', 'b' * 32, 'c' * 32 + ';bad name'])
        self.assertEqual(fu.parse_hashes('abc\n' + 'd' * 40 + '\n', 32), [])

    def test_domain_lists(self):
        self.assertEqual(fu.parse_list('0.0.0.0 a.example\nb.example\n# x\n1.2.3.4 c.example\n'), {'a.example', 'b.example'})


class CategoryLookupTest(unittest.TestCase):
    def test_lookup_finds_parent_entries(self):
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, 'lists'))
            os.makedirs(os.path.join(td, 'seeds'))
            with open(os.path.join(td, 'lists', 'ads.txt'), 'w') as f:
                f.write('tracker.example.com\nads.example.net\n')
            with open(os.path.join(td, 'seeds', 'social.txt'), 'w') as f:
                f.write('social.example\n')
            cfs.LIST_DIR = os.path.join(td, 'lists')
            cfs.SEED_DIR = os.path.join(td, 'seeds')
            out = cfs.lookup('https://www.tracker.example.com/path?x=1')
            self.assertEqual([m['category'] for m in out['matches']], ['ads'])
            out = cfs.lookup('a.b.social.example')
            self.assertEqual(out['matches'][0]['category'], 'social')
            self.assertEqual(out['matches'][0]['list'], 'built-in')
            self.assertEqual(cfs.lookup('clean.example.org')['matches'], [])
            self.assertIn('error', cfs.lookup('not a name'))


class ResolverLogTest(unittest.TestCase):
    LINE = ('<30>1 2026-10-13T15:39:51+00:00 OPNsense.internal unbound 39890 - [meta sequenceId="32"] [39890:1] '
            'info: instagram.com. always_nxdomain 10.77.0.2@60743 www.instagram.com. A IN')

    def test_blocked_lookup_line_is_parsed(self):
        m = cfs.LINE.match(self.LINE)
        self.assertIsNotNone(m)
        self.assertEqual((m.group(2), m.group(3), m.group(4), m.group(5), m.group(6)),
                         ('instagram.com', 'always_nxdomain', '10.77.0.2', 'www.instagram.com', 'A'))
        self.assertEqual(cfs.parse_time('2026-10-13T15:39:51+00:00'), 1791905991)

    def test_other_lines_are_ignored(self):
        self.assertIsNone(cfs.LINE.match('<30>1 2026-10-13T15:39:51+00:00 host unbound 1 - [meta] [1:1] info: something else'))


if __name__ == '__main__':
    unittest.main()
