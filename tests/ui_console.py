#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Browser test (Playwright) of the 0.4.0 console: menus, Live Sessions and its
# quick action dialog, Web Control rule dialog with a wildcard, one-click
# Application Control and CFS categories, the antivirus file scan, and a phone
# sized window.
#
#   python tests/ui_console.py [screenshot-dir]

import os
import sys
import tempfile

from playwright.sync_api import sync_playwright

HOST = os.environ.get('OPN_HOST', '192.168.1.12')
USER = os.environ.get('OPN_UI_USER', 'root')
PASS = os.environ.get('OPN_UI_PASS', 'opnsense')
EICAR = 'X5O!P%@AP[4' + chr(92) + 'PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def check(ok, text):
    print(('PASS ' if ok else 'FAIL ') + text)
    return 0 if ok else 1


def main():
    shots = sys.argv[1] if len(sys.argv) > 1 else None
    failed = 0
    errors = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(ignore_https_errors=True, viewport={'width': 1400, 'height': 1000})
        page = ctx.new_page()
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.on('console', lambda m: errors.append(m.text) if m.type == 'error' and 'favicon' not in m.text else None)
        page.goto('https://%s/' % HOST)
        page.fill('input[name=usernamefld]', USER)
        page.fill('input[name=passwordfld]', PASS)
        page.click('button[type=submit], input[type=submit]')
        page.wait_for_load_state('networkidle')

        def shot(name):
            if shots:
                os.makedirs(shots, exist_ok=True)
                page.screenshot(path=os.path.join(shots, name))

        def open_page(path):
            page.goto('https://%s/ui/layer7security/%s' % (HOST, path))
            page.wait_for_load_state('networkidle')
            page.wait_for_timeout(1500)

        # ---- menu: three groups with the requested entries
        open_page('webcontrol')
        text = page.locator('#mainmenu').inner_text()
        failed += check(all(x in text for x in ('Layer 7', 'Protection', 'AI')), 'the sidebar has the Layer 7, Protection and AI menus')
        for entry in ('Web Control', 'Application Control', 'CFS', 'DPI-SSL', 'AI Service', 'AI Inspection', 'AI Audit', 'Live Sessions'):
            failed += check(page.locator('#mainmenu a', has_text=entry).count() > 0, 'menu entry: ' + entry)

        # ---- Web Control: add a wildcard rule through the dialog, test box, delete
        open_page('webcontrol')
        page.click('a[href="#tab-rules"]')
        page.click('#wc-add-quick')
        page.wait_for_selector('#DialogWebRule', state='visible')
        page.fill('#rule\\.value', 'HTTPS://*UiTest-Wild.example/some/path')
        page.select_option('#rule\\.action', 'block')
        page.fill('#rule\\.description', 'ui test')
        page.click('#btn_DialogWebRule_save')
        page.wait_for_timeout(1800)
        page.wait_for_load_state('networkidle')
        grid = page.locator('#grid-rules').inner_text()
        failed += check('*uitest-wild.example' in grid, 'a pasted URL with a wildcard is stored as a clean pattern')
        shot('ui_webcontrol_rules.png')
        page.click('a[href="#tab-test"]')
        page.fill('#wc-test-q', 'www.uitest-wild.example')
        page.click('#wc-test-go')
        page.wait_for_timeout(1500)
        failed += check('blocked' in page.locator('#wc-test-out').inner_text().lower(), 'the test box says the site is blocked')
        page.click('a[href="#tab-rules"]')
        row = page.locator('#grid-rules .tabulator-row, #grid-rules tbody tr', has_text='uitest-wild')
        if row.count():
            row.first.locator('button.command-delete').click()
            page.wait_for_selector('.bootstrap-dialog.in .btn-warning')
            page.click('.bootstrap-dialog.in .btn-warning')
            page.wait_for_timeout(1500)
        failed += check('uitest-wild' not in page.locator('#grid-rules').inner_text(), 'the rule can be deleted again')

        # ---- Live Sessions: list, filters, details dialog, quick action dialog (cancelled)
        open_page('live')
        failed += check(page.locator('#live-tiles .l7-tile').count() >= 5, 'live tiles are shown')
        failed += check(page.locator('#tbl-conn tbody tr').count() >= 1, 'the live table has rows')
        shot('ui_live.png')
        page.click('.l7-chip[data-dir=firewall]')
        page.wait_for_timeout(1500)
        page.click('.l7-chip[data-dir=firewall]')
        page.click('#live-pause')
        failed += check('Paused' in page.locator('#live-foot').inner_text(), 'pause freezes the list')
        page.click('#live-pause')
        page.locator('#tbl-conn .act-block').first.click()
        page.wait_for_selector('.bootstrap-dialog.in')
        dlg = page.locator('.bootstrap-dialog.in').inner_text()
        failed += check('How long' in dlg and 'What' in dlg and 'For' in dlg, 'the block dialog asks what, for whom and how long')
        shot('ui_live_block_dialog.png')
        page.click('.bootstrap-dialog.in .modal-footer button >> text=Cancel')
        page.wait_for_timeout(500)
        page.locator('#tbl-conn .act-info').first.click()
        page.wait_for_selector('.bootstrap-dialog.in')
        failed += check('Session details' in page.locator('.bootstrap-dialog.in').inner_text(), 'the details dialog opens')
        page.click('.bootstrap-dialog.in .modal-footer button >> text=Close')
        page.click('a[href="#tab-history"]')
        page.wait_for_timeout(2000)
        failed += check(page.locator('#grid-flows').count() == 1, 'the history tab shows the stored flows')
        # quick action from the history list: block a website for one hour, check it in Web Control, remove it
        btn = page.locator('#grid-flows .hist-block:not([data-host=""])')
        if btn.count():
            host = btn.first.get_attribute('data-host')
            btn.first.click()
            page.wait_for_selector('.bootstrap-dialog.in')
            page.select_option('#qa-long', '60')
            page.click('#qa-yes')
            page.wait_for_selector('.l7-toast', timeout=60000)
            toast = page.locator('.l7-toast').first.inner_text()
            failed += check('Active now' in toast, 'the quick action reports success (%s)' % toast[:70])
            open_page('webcontrol')
            page.click('a[href="#tab-rules"]')
            grid = page.locator('#grid-rules').inner_text()
            failed += check(host in grid and 'in ' in grid, 'the rule for %s shows up in Web Control as a temporary rule' % host)
            shot('ui_webcontrol_after_quick.png')
            row = page.locator('#grid-rules tbody tr', has_text=host)
            while row.count():
                row.first.locator('button.command-delete').click()
                page.wait_for_selector('.bootstrap-dialog.in .btn-warning')
                page.click('.bootstrap-dialog.in .btn-warning')
                page.wait_for_timeout(1500)
                row = page.locator('#grid-rules tbody tr', has_text=host)
            page.click('#reconfigureAct')
            page.wait_for_timeout(9000)
        else:
            print('SKIP quick action from history (no stored flow with a website name)')

        # ---- Application Control: one-click category, then undo
        open_page('appcontrol')
        page.check('input[data-group=categories][data-key=Mining][value=monitor]')
        page.click('#cats-save')
        page.wait_for_timeout(1500)
        page.reload()
        page.wait_for_load_state('networkidle')
        page.wait_for_timeout(1500)
        failed += check(page.locator('input[data-group=categories][data-key=Mining][value=monitor]').is_checked(), 'a category choice is saved')
        page.check('input[data-group=categories][data-key=Mining][value=allow]')
        page.click('#cats-save')
        page.wait_for_timeout(1500)
        shot('ui_appcontrol.png')

        # ---- CFS: categories tab and test box
        open_page('cfs')
        page.click('a[href="#tab-cats"]')
        failed += check(page.locator('#tbl-cats .cat-on').count() >= 9, 'the CFS categories are listed')
        page.click('a[href="#tab-test"]')
        page.fill('#cfs-test-q', 'www.example.com')
        page.click('#cfs-test-go')
        page.wait_for_timeout(2500)
        failed += check(page.locator('#cfs-test-out').inner_text().strip() != '', 'the category test answers')
        page.click('a[href="#tab-cloud"]')
        page.wait_for_timeout(800)
        shot('ui_cfs_cloud.png')

        # ---- Antivirus: scan the EICAR test file through the GUI
        open_page('antivirus')
        page.click('a[href="#tools"]')
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.com')
        tmp.write(EICAR.encode())
        tmp.close()
        page.set_input_files('#scan-file', tmp.name)
        page.click('#scanAct')
        page.wait_for_timeout(3500)
        out = page.locator('#scan-result').inner_text()
        os.unlink(tmp.name)
        failed += check('Malware found' in out, 'the file scan recognises the EICAR test file (%s)' % out[:40].replace('\n', ' '))
        page.fill('#check-hash', '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
        page.click('#checkAct')
        page.wait_for_timeout(1500)
        failed += check('EICAR' in page.locator('#check-result').inner_text(), 'the hash lookup knows the EICAR hash')
        shot('ui_antivirus_tools.png')

        # ---- the other module pages render their header and tiles
        for path, title in (('dpissl', 'DPI-SSL'), ('access', 'Users and Access'), ('ai', 'AI Service'), ('inspection', 'AI Inspection'), ('audit', 'AI Audit'),
                            ('dashboard', 'Layer 7 Overview'), ('settings', 'Layer 7 Settings'), ('geoip', 'GeoIP'), ('macbinding', 'MAC Binding')):
            open_page(path)
            head = page.locator('.l7-head-text h1').inner_text()
            failed += check(head == title, 'page %s has the header "%s"' % (path, head))
            failed += check(page.locator('#reconfigureAct, .l7-tiles').count() >= 1, '%s shows its controls' % path)

        # ---- phone sized window: nothing overflows the page horizontally
        page.set_viewport_size({'width': 390, 'height': 800})
        for path in ('live', 'webcontrol', 'cfs', 'dpissl'):
            open_page(path)
            overflow = page.evaluate('document.documentElement.scrollWidth - document.documentElement.clientWidth')
            failed += check(overflow <= 8, '%s fits a phone width (overflow %dpx)' % (path, overflow))
        shot('ui_phone_live.png')
        failed += check(not errors, 'no JavaScript errors (%s)' % '; '.join(errors)[:160])
        browser.close()
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
