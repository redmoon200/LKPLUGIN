#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# The Lobby widget is declared in an XML file that the dashboard reads: a typo there hides the widget for every
# customer, so check that the declaration is well formed and points at files that exist.

import os
import unittest
import xml.etree.ElementTree as ET

WIDGETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'security', 'layer7security', 'src', 'opnsense', 'www', 'js', 'widgets')
IMG = os.path.join(WIDGETS, '..', '..', 'img', 'layer7security', 'logo.png')


class WidgetTest(unittest.TestCase):
    def setUp(self):
        self.root = ET.parse(os.path.join(WIDGETS, 'Metadata', 'Layer7Security.xml')).getroot()
        self.w = self.root.find('layer7security')

    def test_declared_file_exists(self):
        self.assertIsNotNone(self.w)
        self.assertTrue(os.path.isfile(os.path.join(WIDGETS, self.w.findtext('filename'))))

    def test_endpoints_are_plugin_api_routes(self):
        urls = [e.text for e in self.w.find('endpoints')]
        self.assertTrue(urls)
        for u in urls:
            self.assertTrue(u.startswith('/api/layer7security/'), u)

    def test_every_translation_the_script_uses_is_declared(self):
        names = {t.tag for t in self.w.find('translations')}
        src = open(os.path.join(WIDGETS, 'Layer7Security.js'), encoding='utf-8').read()
        import re
        used = set(re.findall(r'translations\.(\w+)', src)) | set(re.findall(r'\bt\.(\w+)', src))
        self.assertFalse(used - names, 'not declared: %s' % sorted(used - names))
        self.assertIn('title', names)

    def test_logo_is_shipped(self):
        self.assertTrue(os.path.isfile(IMG))
        src = open(os.path.join(WIDGETS, 'Layer7Security.js'), encoding='utf-8').read()
        self.assertIn('/ui/img/layer7security/logo.png', src)


if __name__ == '__main__':
    unittest.main()
