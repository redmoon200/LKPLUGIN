#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Browser test (Playwright) of the cloud server dashboard: sign-in, the pages,
# the license generator (create, copy box, revoke and reinstate), a phone sized window.
# The admin password is read from ~/.lk-secrets/cloud_admin.txt.
#
#   python tests/ui_cloud.py [screenshot-dir]

import os
import sys
import time

from playwright.sync_api import sync_playwright

BASE = os.environ.get('L7_DASH', 'http://192.168.1.73:8090')
PW = open(os.path.join(os.path.expanduser('~'), '.lk-secrets', 'cloud_admin.txt')).read().strip()


def check(ok, text):
    print(('PASS ' if ok else 'FAIL ') + text)
    return 0 if ok else 1


def main():
    shots = sys.argv[1] if len(sys.argv) > 1 else None
    failed = 0
    errors = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={'width': 1400, 'height': 1000})
        page = ctx.new_page()
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.on('console', lambda m: errors.append(m.text) if m.type == 'error' and 'favicon' not in m.text and '401' not in m.text and '400' not in m.text else None)

        def shot(name):
            if shots:
                os.makedirs(shots, exist_ok=True)
                page.screenshot(path=os.path.join(shots, name), full_page=True)

        page.goto(BASE + '/')
        page.wait_for_selector('#login', state='visible')
        failed += check(page.locator('#loginform').count() == 1, 'the dashboard asks for a password')
        page.fill('#pw', 'not the password')
        page.click('#loginform button[type=submit]')
        page.wait_for_timeout(800)
        failed += check('Wrong password' in page.locator('#loginerr').inner_text(), 'a wrong password is refused')
        page.fill('#pw', PW)
        page.click('#loginform button[type=submit]')
        page.wait_for_selector('#app', state='visible')
        page.wait_for_selector('.tile')

        # ---- overview
        page.wait_for_timeout(800)
        failed += check(page.locator('.tile').count() >= 8, 'the overview shows its tiles')
        failed += check('last build' in page.locator('#view').inner_text().lower(), 'the overview shows the last build')
        failed += check(page.locator('#hist tbody tr').count() >= 1, 'the build history is listed')
        shot('cloud_overview.png')

        # ---- feeds
        page.click('nav a[href="#feeds"]')
        page.wait_for_selector('.bpart')
        page.wait_for_timeout(500)
        text = page.locator('#view').inner_text()
        failed += check('manifest.json' in text and 'ads.txt' in text, 'the feeds page lists the published files')
        failed += check(page.locator('#view table').nth(1).locator('tbody tr').count() >= 5, 'the sources are listed')
        shot('cloud_feeds.png')

        # ---- firewalls
        page.click('nav a[href="#firewalls"]')
        page.wait_for_selector('#view table')
        page.wait_for_timeout(500)
        failed += check(page.locator('#view tbody tr').count() >= 1 and 'No firewall' not in page.locator('#view tbody').inner_text(), 'firewalls that checked in are listed')
        page.locator('.fwd').first.click()
        page.wait_for_selector('#modal.on')
        failed += check('installation id' in page.locator('#modalbox').inner_text().lower(), 'a firewall opens its details')
        page.click('#mclose')
        shot('cloud_firewalls.png')

        # ---- license generator
        page.click('nav a[href="#licenses"]')
        page.wait_for_selector('#g_go')
        name = 'UI test %d' % int(time.time())
        page.fill('#g_cust', name)
        page.select_option('#g_type', 'year')
        page.click('#g_go')
        page.wait_for_selector('#keytxt')
        key = page.locator('#keytxt').inner_text().strip()
        failed += check(len(key.replace('-', '')) == 138 and key.count('-') >= 25, 'the generator shows a new key (%d characters)' % len(key))
        failed += check(page.locator('tbody tr', has_text=name).count() == 1, 'the new license is in the list')
        shot('cloud_licenses.png')
        page.once('dialog', lambda d: d.accept())
        page.locator('tbody tr', has_text=name).locator('.rev').click()
        page.wait_for_timeout(1000)
        failed += check('revoked' in page.locator('tbody tr', has_text=name).inner_text(), 'a license can be revoked')
        page.locator('tbody tr', has_text=name).locator('.rev').click()
        page.wait_for_timeout(1000)
        failed += check('active' in page.locator('tbody tr', has_text=name).inner_text(), 'and reinstated')
        page.fill('#g_cust', '')
        page.click('#g_go')
        page.wait_for_timeout(800)
        failed += check(page.locator('#toast div.bad').count() >= 1, 'a missing customer name is refused')

        # ---- activity and settings
        page.click('nav a[href="#activity"]')
        page.wait_for_selector('#view table')
        page.wait_for_timeout(500)
        failed += check('/feeds/' in page.locator('#view').inner_text() or '/api/v1' in page.locator('#view').inner_text(), 'the activity page lists requests')
        page.click('nav a[href="#settings"]')
        page.wait_for_selector('#s_save')
        failed += check(len(page.locator('#view .key').first.inner_text().strip()) == 44, 'the settings page shows the public key')
        shot('cloud_settings.png')

        # ---- phone width
        page.set_viewport_size({'width': 390, 'height': 800})
        for h in ('overview', 'feeds', 'firewalls', 'licenses'):
            page.goto(BASE + '/#' + h)
            page.reload()
            page.wait_for_selector('#view h1')
            page.wait_for_timeout(700)
            over = page.evaluate('document.documentElement.scrollWidth - document.documentElement.clientWidth')
            failed += check(over <= 2, '%s fits a phone width (overflow %dpx)' % (h, over))
        shot('cloud_phone.png')

        # ---- sign out
        page.set_viewport_size({'width': 1400, 'height': 1000})
        page.click('#logout')
        page.wait_for_selector('#login', state='visible')
        failed += check(True, 'signing out returns to the sign-in form')
        browser.close()
    failed += check(not errors, 'no JavaScript errors (%s)' % '; '.join(errors)[:200])
    print('failed: %d' % failed)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
