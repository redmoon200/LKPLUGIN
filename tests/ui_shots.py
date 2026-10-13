#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Drives a real browser (Playwright/Chromium) through the plugin GUI, records
# JavaScript console errors and saves screenshots.
#
#   python tests/ui_shots.py OUTDIR

import os
import sys

from playwright.sync_api import sync_playwright

HOST = os.environ.get('OPN_HOST', '192.168.1.12')
USER = os.environ.get('OPN_UI_USER', 'root')
PASS = os.environ.get('OPN_UI_PASS', 'opnsense')
PAGES = ['dashboard', 'flows', 'policies', 'users', 'dns', 'settings']


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else 'shots'
    os.makedirs(out, exist_ok=True)
    errors = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(ignore_https_errors=True, viewport={'width': 1400, 'height': 1000})
        page = ctx.new_page()
        page.on('console', lambda m: errors.append((page.url, m.text)) if m.type == 'error' else None)
        page.on('pageerror', lambda e: errors.append((page.url, 'pageerror: %s' % e)))
        page.goto('https://%s/' % HOST)
        page.fill('input[name=usernamefld]', USER)
        page.fill('input[name=passwordfld]', PASS)
        page.click('button[type=submit], input[type=submit]')
        page.wait_for_load_state('networkidle')
        for name in PAGES:
            page.goto('https://%s/ui/layer7security/%s' % (HOST, name))
            page.wait_for_load_state('networkidle')
            page.wait_for_timeout(2500)
            page.screenshot(path=os.path.join(out, name + '.png'), full_page=False)
            print('shot', name)
        browser.close()
    real = [e for e in errors if 'favicon' not in e[1] and 'Failed to load resource' not in e[1]]
    for url, text in real:
        print('JS ERROR', url, text[:200])
    print('js errors:', len(real))
    return 1 if real else 0


if __name__ == '__main__':
    sys.exit(main())
