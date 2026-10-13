#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Browser test of the GeoIP and MAC binding pages: create a GeoIP policy and a
# binding through the dialogs, bind a discovered device with one click, check
# the grids, then delete everything again through the grid.
#
#   python tests/ui_crud2.py [screenshot-dir]

import os
import sys

from playwright.sync_api import sync_playwright

HOST = os.environ.get('OPN_HOST', '192.168.1.12')
USER = os.environ.get('OPN_UI_USER', 'root')
PASS = os.environ.get('OPN_UI_PASS', 'opnsense')


def check(ok, text):
    print(('PASS ' if ok else 'FAIL ') + text)
    return 0 if ok else 1


def select_options(page, select_id, values):
    page.evaluate("""([id, vals]) => { const s = document.getElementById(id);
        for (const o of s.options) { o.selected = vals.includes(o.value); }
        $(s).selectpicker && $(s).selectpicker('refresh'); }""", [select_id, values])


def delete_row(page, grid, text):
    row = page.locator('%s .tabulator-row' % grid, has_text=text)
    if row.count() == 0:
        return False
    row.first.locator('button.command-delete').click()
    page.wait_for_selector('.bootstrap-dialog.in .btn-warning')
    page.click('.bootstrap-dialog.in .btn-warning')
    page.wait_for_timeout(1500)
    return True


def main():
    shots = sys.argv[1] if len(sys.argv) > 1 else None
    failed = 0
    errors = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(ignore_https_errors=True, viewport={'width': 1400, 'height': 1100})
        page = ctx.new_page()
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.goto('https://%s/' % HOST)
        page.fill('input[name=usernamefld]', USER)
        page.fill('input[name=passwordfld]', PASS)
        page.click('button[type=submit], input[type=submit]')
        page.wait_for_load_state('networkidle')

        # ---- GeoIP policy through the dialog
        page.goto('https://%s/ui/layer7security/geoip' % HOST)
        page.wait_for_load_state('networkidle')
        page.click('button.command-add')
        page.wait_for_selector('#DialogGeo', state='visible')
        n_countries = page.evaluate("document.getElementById('geopolicy.countries').options.length")
        failed += check(n_countries > 200, 'country selector has %d entries' % n_countries)
        page.fill('#geopolicy\\.name', 'ui-geo-test')
        page.select_option('#geopolicy\\.action', 'block')
        page.select_option('#geopolicy\\.direction', 'out')
        select_options(page, 'geopolicy.countries', ['DE', 'FR'])
        page.click('#btn_DialogGeo_save')
        page.wait_for_timeout(1500)
        page.wait_for_load_state('networkidle')
        failed += check('ui-geo-test' in page.content(), 'GeoIP policy created through the dialog')
        if shots:
            os.makedirs(shots, exist_ok=True)
            page.screenshot(path=os.path.join(shots, 'geoip_grid.png'))
        failed += check(delete_row(page, '#grid-geo', 'ui-geo-test'), 'GeoIP policy deleted through the grid')

        # ---- MAC binding through the dialog
        page.goto('https://%s/ui/layer7security/macbinding' % HOST)
        page.wait_for_load_state('networkidle')
        page.click('button.command-add')
        page.wait_for_selector('#DialogBinding', state='visible')
        page.fill('#binding\\.name', 'ui-bind-test')
        page.fill('#binding\\.mac', '02:11:22:33:44:55')
        page.fill('#binding\\.ip', '10.77.0.201')
        page.click('#btn_DialogBinding_save')
        page.wait_for_timeout(1500)
        page.wait_for_load_state('networkidle')
        failed += check('ui-bind-test' in page.content(), 'binding created through the dialog')

        # a malformed MAC must be refused by the form
        page.click('button.command-add')
        page.wait_for_selector('#DialogBinding', state='visible')
        page.fill('#binding\\.name', 'ui-bad-mac')
        page.fill('#binding\\.mac', 'not-a-mac')
        page.click('#btn_DialogBinding_save')
        page.wait_for_timeout(1200)
        failed += check('ui-bad-mac' not in page.locator('#grid-bindings').inner_text(), 'invalid MAC rejected by validation')
        page.click('#DialogBinding button[data-dismiss=modal].btn-default')   # Cancel
        page.wait_for_selector('#DialogBinding', state='hidden')

        # ---- one-click bind from the discovered devices list
        page.click('a[href="#devices"]')
        page.wait_for_timeout(2500)
        bind = page.locator('#tbl-devices .bind-btn')
        if bind.count():
            if shots:
                page.screenshot(path=os.path.join(shots, 'macbinding_devices.png'))
            bind.first.click()
            page.wait_for_timeout(2500)
            page.click('a[href="#bindings"]')
            page.wait_for_timeout(1000)
            failed += check('bound from the discovered devices list' in page.content() or 'device-' in page.content(),
                            'Bind button created a binding from a discovered device')
        else:
            print('SKIP no unbound device in the list')

        # ---- clean up through the grid
        page.goto('https://%s/ui/layer7security/macbinding' % HOST)
        page.wait_for_load_state('networkidle')
        page.wait_for_timeout(1000)
        removed = delete_row(page, '#grid-bindings', 'ui-bind-test')
        while delete_row(page, '#grid-bindings', 'device-'):
            pass
        failed += check(removed, 'test bindings deleted through the grid')
        failed += check(not errors, 'no JavaScript errors (%s)' % '; '.join(errors)[:120])
        browser.close()
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
