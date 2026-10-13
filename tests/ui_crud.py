#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Browser test of the policy and user dialogs: open the dialog, check that the
# application/category selectors are populated from the engine catalog, create
# an entry through the form, see it in the grid, then delete it again.
#
#   python tests/ui_crud.py [screenshot-dir]

import os
import sys

from playwright.sync_api import sync_playwright

HOST = os.environ.get('OPN_HOST', '192.168.1.12')
USER = os.environ.get('OPN_UI_USER', 'root')
PASS = os.environ.get('OPN_UI_PASS', 'opnsense')


def check(ok, text):
    print(('PASS ' if ok else 'FAIL ') + text)
    return 0 if ok else 1


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

        # ---- user
        page.goto('https://%s/ui/layer7security/users' % HOST)         # forwards to Users and Access
        page.wait_for_load_state('networkidle')
        page.click('a[href="#tab-users"]')
        page.wait_for_timeout(800)
        page.click('#grid-users button.command-add, #grid-users-footer button.command-add, button.command-add')
        page.wait_for_selector('#DialogUser', state='visible')
        page.fill('#user\\.name', 'ui-test-user')
        page.evaluate("""() => { const s = document.getElementById('user.addresses');
            const o = document.createElement('option'); o.value = '10.77.0.99'; o.text = '10.77.0.99'; o.selected = true;
            s.appendChild(o); $(s).selectpicker && $(s).selectpicker('refresh'); }""")
        page.click('#btn_DialogUser_save')
        page.wait_for_timeout(1500)
        page.wait_for_load_state('networkidle')
        failed += check('ui-test-user' in page.content(), 'user created through the dialog and shown in the grid')

        # ---- policy
        page.goto('https://%s/ui/layer7security/policies' % HOST)      # forwards to Application Control
        page.wait_for_load_state('networkidle')
        page.click('a[href="#tab-rules"]')
        page.wait_for_timeout(800)
        page.click('button.command-add')
        page.wait_for_selector('#DialogPolicy', state='visible')
        n_apps = page.evaluate("document.getElementById('policy.applications').options.length")
        n_cats = page.evaluate("document.getElementById('policy.categories').options.length")
        failed += check(n_apps > 300, 'application selector has %d entries from the nDPI catalog' % n_apps)
        failed += check(n_cats > 30, 'category selector has %d entries' % n_cats)
        if shots:
            os.makedirs(shots, exist_ok=True)
            page.screenshot(path=os.path.join(shots, 'policy_dialog.png'))
        page.fill('#policy\\.name', 'ui-test-policy')
        page.select_option('#policy\\.action', 'monitor')
        page.evaluate("""() => { const s = document.getElementById('policy.applications');
            for (const o of s.options) { if (o.value === 'TikTok') { o.selected = true; } }
            $(s).selectpicker && $(s).selectpicker('refresh'); }""")
        page.click('#btn_DialogPolicy_save')
        page.wait_for_timeout(1500)
        page.wait_for_load_state('networkidle')
        content = page.content()
        failed += check('ui-test-policy' in content and 'TikTok' in content,
                        'policy created through the dialog, application shown in the grid')
        if shots:
            page.screenshot(path=os.path.join(shots, 'policy_grid.png'))

        # ---- clean up through the grid's delete buttons (Tabulator rows)
        def delete_row(grid, text):
            row = page.locator('%s .tabulator-row' % grid, has_text=text)
            if row.count() == 0:
                return False
            row.first.locator('button.command-delete').click()
            page.wait_for_selector('.bootstrap-dialog.in .btn-warning')
            page.click('.bootstrap-dialog.in .btn-warning')
            page.wait_for_timeout(1500)
            return True

        ok_pol = delete_row('#grid-policies', 'ui-test-policy')
        page.goto('https://%s/ui/layer7security/users' % HOST)
        page.wait_for_load_state('networkidle')
        page.click('a[href="#tab-users"]')
        page.wait_for_timeout(1000)
        ok_usr = delete_row('#grid-users', 'ui-test-user')
        failed += check(ok_pol and ok_usr, 'test policy and user deleted through the grid')
        page.reload()
        page.wait_for_load_state('networkidle')
        page.wait_for_timeout(1500)
        failed += check('ui-test-user' not in page.locator('#grid-users').inner_text(), 'user is gone after reload')
        failed += check(not errors, 'no JavaScript errors (%s)' % '; '.join(errors)[:120])
        browser.close()
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
