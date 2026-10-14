#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Browser test (Playwright) of the locked state: with no license every Layer 7 page opens the License
# page, a wrong key is refused, a key from the cloud dashboard unlocks the plugin again.
# Removes the license of the lab firewall and puts a lifetime key back at the end.
#
#   python tests/ui_license.py [screenshot-dir]

import base64
import http.cookiejar
import json
import os
import ssl
import sys
import urllib.request

from playwright.sync_api import sync_playwright

HOST = os.environ.get('OPN_HOST', '192.168.1.12')
USER = os.environ.get('OPN_UI_USER', 'root')
PASS = os.environ.get('OPN_UI_PASS', 'opnsense')
DASH = os.environ.get('L7_DASH', 'http://192.168.1.73:8090')
SECRETS = os.path.join(os.path.expanduser('~'), '.lk-secrets')
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def check(ok, text):
    print(('PASS ' if ok else 'FAIL ') + text)
    return 0 if ok else 1


def opn_api(method, path, body=None):
    k = json.load(open(os.path.join(SECRETS, 'opn_api.json')))
    auth = base64.b64encode(('%s:%s' % (k['key'], k['secret'])).encode()).decode()
    req = urllib.request.Request('https://%s%s' % (HOST, path), method=method, data=json.dumps(body if body is not None else {}).encode() if method == 'POST' else None,
                                 headers=dict({'Authorization': 'Basic ' + auth}, **({'Content-Type': 'application/json'} if method == 'POST' else {})))
    return json.load(urllib.request.urlopen(req, context=CTX, timeout=120))


def dash_issue(install_id):
    pw = open(os.path.join(SECRETS, 'cloud_admin.txt')).read().strip()
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def call(path, body):
        req = urllib.request.Request(DASH + path, data=json.dumps(body).encode(),
                                     headers={'X-Requested-With': 'l7dash', 'Content-Type': 'application/json'})
        return json.load(op.open(req, timeout=30))
    call('/api/login', {'password': pw})
    return call('/api/licenses/issue', {'type': 'lifetime', 'customer': 'ui license test', 'install_id': install_id, 'note': 'ui test'})['license']['key']


def main():
    shots = sys.argv[1] if len(sys.argv) > 1 else None
    failed = 0
    errors = []
    install_id = opn_api('GET', '/api/layer7security/license/status')['license']['install_id']
    key = dash_issue(install_id)
    opn_api('POST', '/api/layer7security/license/remove')
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context(ignore_https_errors=True, viewport={'width': 1400, 'height': 1000})
            page = ctx.new_page()
            page.on('pageerror', lambda e: errors.append(str(e)))
            page.goto('https://%s/' % HOST)
            page.fill('input[name=usernamefld]', USER)
            page.fill('input[name=passwordfld]', PASS)
            page.click('button[type=submit], input[type=submit]')
            page.wait_for_load_state('networkidle')

            def shot(name):
                if shots:
                    os.makedirs(shots, exist_ok=True)
                    page.screenshot(path=os.path.join(shots, name))

            for path in ('webcontrol', 'live', 'settings', 'ai', 'dashboard'):
                page.goto('https://%s/ui/layer7security/%s' % (HOST, path))
                page.wait_for_load_state('networkidle')
                failed += check(page.url.rstrip('/').endswith('/ui/layer7security/license'), 'without a license /%s opens the License page' % path)
            page.wait_for_timeout(1500)
            failed += check(page.locator('#lic-locked').is_visible(), 'the page says the protection is switched off')
            failed += check('no license' in page.locator('#lic-tiles').inner_text().lower(), 'the state tile says "No license"')
            failed += check(page.locator('#lic-trial').is_visible(), 'the trial button is offered')
            failed += check(page.locator('#lic-install').inner_text().strip() == install_id, 'the installation id is shown')
            shot('ui_license_locked.png')

            page.fill('#lic-key', 'ABCDE-FGHIJ-KLMNO-PQRST-UVWXY-' * 5)
            page.click('#lic-activate')
            page.wait_for_timeout(2500)
            failed += check(page.locator('.l7-toast').count() >= 1 and 'no license' in page.locator('#lic-tiles').inner_text().lower(), 'a wrong key is refused')

            page.fill('#lic-key', key)
            page.click('#lic-activate')
            page.wait_for_function("document.querySelector('#lic-tiles').innerText.toLowerCase().includes('active')", timeout=60000)
            failed += check(not page.locator('#lic-locked').is_visible(), 'the right key unlocks the plugin')
            failed += check('lifetime' in page.locator('#lic-tiles').inner_text().lower(), 'the lifetime license is shown')
            failed += check(not page.locator('#lic-trial').is_visible(), 'the trial button is gone')
            shot('ui_license_active.png')
            page.goto('https://%s/ui/layer7security/webcontrol' % HOST)
            page.wait_for_load_state('networkidle')
            failed += check(page.locator('.l7-head-text h1').inner_text() == 'Web Control', 'Web Control opens again')
            browser.close()
    finally:
        st = opn_api('GET', '/api/layer7security/license/status')['license']
        if not st['valid']:
            opn_api('POST', '/api/layer7security/license/activate', {'key': key})
    failed += check(not errors, 'no JavaScript errors (%s)' % '; '.join(errors)[:200])
    print('failed: %d' % failed)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
