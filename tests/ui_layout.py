#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Layout check of the Layer 7 pages in a real browser (Playwright/Chromium), at several window widths:
#   - nothing sticks out of its box (a long IPv6 address or host name in a table must wrap, not cross into the next box)
#   - no table scrolls inside a small box of its own (the grids grow with their rows)
#   - the history grid shows every row when "All" is chosen, and the last row can be reached by scrolling
#
#   python tests/ui_layout.py        (OPN_HOST, OPN_UI_USER, OPN_UI_PASS as in the other ui_ tests)

import json
import os
import sys

from playwright.sync_api import sync_playwright

HOST = os.environ.get('OPN_HOST', '192.168.1.12')
USER = os.environ.get('OPN_UI_USER', 'root')
PASS = os.environ.get('OPN_UI_PASS', 'opnsense')
PAGES = ['dashboard', 'live', 'access', 'macbinding', 'geoip', 'license', 'settings', 'webcontrol', 'appcontrol', 'cfs', 'dpissl', 'antivirus', 'ai', 'inspection', 'audit']
WIDTHS = [1500, 1100, 800]

# add long names to the two tables of the overview: this is what real devices look like
LONG_NAMES = """
() => {
  const row = (d) => '<tr><td class="mono">' + d + '</td><td class="num">1204</td><td class="num">98.76 MB</td><td class="num">12.34 MB</td><td class="num">123</td></tr>';
  const t = document.querySelector('#tbl-clients tbody');
  if (t) { t.innerHTML = row('2001:0db8:85a3:0000:0000:8a2e:0370:7334') + row('fe80::be24:11ff:fe91:202%vlan0.10') + row('laptop-of-a-very-long-hostname.office.example.com'); }
  const b = document.querySelector('#tbl-blocks tbody');
  if (b) { b.innerHTML = '<tr><td>Web Control: block a-very-long-rule-name-for-social-media-sites</td><td>Instagram</td><td>SocialNetwork</td><td class="num">9</td></tr>'; }
}
"""

SCAN = """
() => {
  const out = {sticks: [], innerScroll: [], overlap: []};
  const cards = [...document.querySelectorAll('.l7-card, .l7-tile')].filter(e => e.offsetParent !== null);
  for (const c of cards) {
    const cr = c.getBoundingClientRect();
    if (cr.width < 5) continue;
    let worst = null;
    for (const d of c.querySelectorAll('*')) {
      if (d.closest('.dropdown-menu, .modal, .bootstrap-select, .tooltip, .popover, .chart, canvas, .l7-scroll')) continue;
      const s = getComputedStyle(d);
      if (s.position === 'fixed' || s.display === 'none' || s.visibility === 'hidden') continue;
      const r = d.getBoundingClientRect();
      if (r.width < 2 || r.height < 2) continue;
      const over = r.right - cr.right;
      if (over > 2 && (!worst || over > worst.over)) worst = {over: Math.round(over), el: d.tagName + '.' + String(d.className).slice(0, 30)};
    }
    if (worst) out.sticks.push(Object.assign({box: (c.querySelector('h3, .v') || c).innerText.slice(0, 30)}, worst));
  }
  for (const h of document.querySelectorAll('.tabulator-tableholder')) {
    if (h.offsetParent !== null && h.scrollHeight > h.clientHeight + 4) out.innerScroll.push({id: (h.closest('.tabulator') || {}).id, scroll: h.scrollHeight, shown: h.clientHeight});
  }
  const boxes = cards.filter(c => c.classList.contains('l7-card')).map(c => ({c: c, r: c.getBoundingClientRect()}));
  for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
    const a = boxes[i].r, b = boxes[j].r;
    if (boxes[i].c.contains(boxes[j].c) || boxes[j].c.contains(boxes[i].c)) continue;
    if (Math.min(a.right, b.right) - Math.max(a.left, b.left) > 2 && Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 2) out.overlap.push((boxes[i].c.innerText || '').slice(0, 20));
  }
  return out;
}
"""


def login(browser, width):
    page = browser.new_context(ignore_https_errors=True, viewport={'width': width, 'height': 900}).new_page()
    page.goto('https://%s/' % HOST)
    page.fill('input[name=usernamefld]', USER)
    page.fill('input[name=passwordfld]', PASS)
    page.click('button[type=submit], input[type=submit]')
    page.wait_for_load_state('networkidle')
    return page


def main():
    problems = 0
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for width in WIDTHS:
            page = login(browser, width)
            for name in PAGES:
                page.goto('https://%s/ui/layer7security/%s' % (HOST, name))
                page.wait_for_load_state('networkidle')
                page.wait_for_timeout(2500)
                if name == 'dashboard':
                    page.evaluate(LONG_NAMES)
                    page.wait_for_timeout(300)
                result = page.evaluate(SCAN)
                bad = bool(result['sticks'] or result['innerScroll'] or result['overlap'])
                problems += bad
                print('%-11s %4d  %s' % (name, width, 'PROBLEM ' + json.dumps(result) if bad else 'ok'))
            page.context.close()

        # the history grid with "All"
        page = login(browser, 1400)
        page.goto('https://%s/ui/layer7security/live' % HOST)
        page.wait_for_load_state('networkidle')
        page.click('a[href="#tab-history"]')
        page.wait_for_timeout(3000)
        page.locator('button.dropdown-toggle:has-text("25")').first.click()
        with page.expect_response(lambda r: 'flows/search' in r.url) as reply:
            page.locator('.dropdown-menu a:has-text("All")').first.click()
        total = reply.value.json().get('total')
        page.wait_for_timeout(5000)
        shown = page.evaluate("document.querySelectorAll('.tabulator-row').length")
        page.mouse.move(700, 450)
        page.mouse.wheel(0, 500000)
        page.wait_for_timeout(1200)
        last = page.evaluate("(() => { const r = [...document.querySelectorAll('.tabulator-row')].pop(); return r ? r.getBoundingClientRect().bottom : null; })()")
        foot = page.evaluate("document.querySelector('footer, .page-foot').getBoundingClientRect().top")
        capped = min(total, 2000) if total else None
        ok = bool(shown) and total is not None and shown == capped and last is not None and last <= foot + 2
        print('history All: %s rows shown of %s (cap 2000), last row reachable: %s -> %s' % (shown, total, last is not None and last <= foot + 2, 'ok' if ok else 'PROBLEM'))
        problems += not ok
        browser.close()
    print('problems:', problems)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
