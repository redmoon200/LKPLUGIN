#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Logs in to the OPNsense web GUI and fetches every plugin page, checking for
# HTTP 200 and a marker element, so template compile errors are caught.
#
#   OPN_HOST=192.168.1.12 OPN_UI_USER=root OPN_UI_PASS=opnsense tests/ui_check.py

import http.cookiejar
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request

HOST = os.environ.get('OPN_HOST', '192.168.1.12')
USER = os.environ.get('OPN_UI_USER', 'root')
PASS = os.environ.get('OPN_UI_PASS', 'opnsense')
BASE = 'https://%s' % HOST

PAGES = {
    '/ui/layer7security/dashboard': ['c-timeline', 'l7-period', 'dashboard/summary'],
    '/ui/layer7security/flows': ['grid-flows', 'flows/search'],
    '/ui/layer7security/policies': ['grid-policies', 'DialogPolicy', 'search_policy'],
    '/ui/layer7security/users': ['grid-users', 'DialogUser', 'search_user'],
    '/ui/layer7security/dns': ['frm_dns', 'dns/status', 'feedAct'],
    '/ui/layer7security/macbinding': ['grid-bindings', 'DialogBinding', 'frm_mac', 'dashboard/devices'],
    '/ui/layer7security/geoip': ['grid-geo', 'DialogGeo', 'frm_geo', 'geo/update'],
    '/ui/layer7security/ai': ['grid-ai', 'DialogAi', 'search_ai'],
    '/ui/layer7security/audit': ['grid-audit', 'audit/search', 'audit/verify'],
    '/ui/layer7security/inspection': ['frm_inspection', 'inspection/status', 'inspection/ca'],
    '/ui/layer7security/antivirus': ['grid-av', 'frm_antivirus', 'antivirus/search'],
    '/ui/layer7security/settings': ['frm_general', 'layer7security.general.enabled'],
}


def main():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),
                                         urllib.request.HTTPSHandler(context=ctx))

    html = opener.open(BASE + '/', timeout=30).read().decode('utf-8', 'replace')
    fields = dict(re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"', html))
    fields.update({'usernamefld': USER, 'passwordfld': PASS, 'login': '1'})
    resp = opener.open(urllib.request.Request(BASE + '/', urllib.parse.urlencode(fields).encode()), timeout=30)
    body = resp.read().decode('utf-8', 'replace')
    if 'passwordfld' in body and 'Login' in body:
        print('FAIL login')
        return 1
    print('PASS login')

    failed = 0
    for path, markers in PAGES.items():
        try:
            r = opener.open(BASE + path, timeout=60)
            text = r.read().decode('utf-8', 'replace')
            missing = [m for m in markers if m not in text]
            if r.status == 200 and not missing:
                print('PASS %s (%d bytes)' % (path, len(text)))
            else:
                failed += 1
                print('FAIL %s status=%s missing=%s' % (path, r.status, missing))
        except Exception as exc:
            failed += 1
            print('FAIL %s %s' % (path, exc))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
