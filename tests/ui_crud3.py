#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Browser test of the AI Services, AI Audit, AI Inspection and Antivirus pages:
# create and delete an AI rule through its dialog, verify the audit chain with
# the button, scan pasted text in the detector test box, change and restore an
# antivirus setting, look up the EICAR hash.
#
#   python tests/ui_crud3.py [screenshot-dir]

import os
import sys

from playwright.sync_api import sync_playwright

HOST = os.environ.get('OPN_HOST', '192.168.1.12')
USER = os.environ.get('OPN_UI_USER', 'root')
PASS = os.environ.get('OPN_UI_PASS', 'opnsense')
EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'


def check(ok, text):
    print(('PASS ' if ok else 'FAIL ') + text)
    return 0 if ok else 1


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

        def shot(name):
            if shots:
                os.makedirs(shots, exist_ok=True)
                page.screenshot(path=os.path.join(shots, name))

        # ---- AI rule through the dialog
        page.goto('https://%s/ui/layer7security/ai' % HOST)
        page.wait_for_load_state('networkidle')
        page.click('a[href="#rules"]')
        page.wait_for_timeout(500)
        page.click('button.command-add')
        page.wait_for_selector('#DialogAi', state='visible')
        n_services = page.evaluate("document.getElementById('aiservice.service').options.length")
        failed += check(n_services >= 20, 'service selector lists %d AI services' % n_services)
        page.select_option('#aiservice\\.service', 'huggingface')
        page.select_option('#aiservice\\.action', 'block')
        page.fill('#aiservice\\.description', 'ui-ai-test')
        page.click('#btn_DialogAi_save')
        page.wait_for_timeout(1500)
        page.wait_for_load_state('networkidle')
        failed += check('Hugging Face' in page.locator('#grid-ai').inner_text(), 'AI rule created through the dialog')
        shot('ai_rules.png')
        failed += check(delete_row(page, '#grid-ai', 'Hugging Face'), 'AI rule deleted through the grid')

        # ---- audit page: chain verification button
        page.goto('https://%s/ui/layer7security/audit' % HOST)
        page.wait_for_load_state('networkidle')
        page.click('a[href="#integrity"]')
        page.wait_for_timeout(500)
        page.click('#verifyAct')
        page.wait_for_timeout(2500)
        text = page.locator('#verify-result').inner_text().lower()
        failed += check('intact' in text or 'verified' in text or 'ok' in text, 'verify button reports on the chain (%s)' % text[:60])
        shot('audit_integrity.png')

        # ---- inspection page: detector test box
        page.goto('https://%s/ui/layer7security/inspection' % HOST)
        page.wait_for_load_state('networkidle')
        page.click('a[href="#test"]')
        page.fill('#test-text', 'please charge 4111 1111 1111 1111 and use key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789')
        page.click('#testAct')
        page.wait_for_timeout(3000)
        result = page.locator('#test-result').inner_text()
        failed += check('card' in result.lower() and '1111' in result, 'test box finds a card number')
        failed += check('4111 1111 1111 1111' not in result, 'test box shows only the masked excerpt')
        shot('inspection_test.png')
        page.click('a[href="#cert"]')
        page.wait_for_timeout(1000)
        failed += check('SHA-256' in page.locator('#cert').inner_text(), 'certificate tab shows the CA details')

        # ---- antivirus page: change a setting, persist, restore
        page.goto('https://%s/ui/layer7security/antivirus' % HOST)
        page.wait_for_load_state('networkidle')
        page.wait_for_timeout(800)
        before = page.input_value('#layer7security\\.av\\.archiveAction')
        target = 'monitor' if before != 'monitor' else 'off'
        page.select_option('#layer7security\\.av\\.archiveAction', target)
        page.click('#reconfigureAct')
        page.wait_for_timeout(6000)
        page.reload()
        page.wait_for_load_state('networkidle')
        page.wait_for_timeout(800)
        failed += check(page.input_value('#layer7security\\.av\\.archiveAction') == target, 'antivirus setting saved and applied')
        page.select_option('#layer7security\\.av\\.archiveAction', before)
        page.click('#reconfigureAct')
        page.wait_for_timeout(6000)
        page.click('a[href="#status"]')
        page.fill('#check-hash', EICAR_SHA256)
        page.click('#checkAct')
        page.wait_for_timeout(2500)
        failed += check('EICAR' in page.locator('#check-result').inner_text(), 'hash lookup recognises the EICAR test file')
        shot('antivirus_status.png')
        failed += check(not errors, 'no JavaScript errors (%s)' % '; '.join(errors)[:120])
        browser.close()
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
