#!/bin/sh

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Once a minute: when a temporary Web Control rule has run out, remove it and
# apply. The cheap time check comes first, so the PHP framework only starts when
# there is something to do.

f=/var/db/layer7security/web_expiry
[ -s "$f" ] || exit 0
next=$(cat "$f")
[ "$next" -gt 0 ] 2>/dev/null || exit 0
[ "$(date +%s)" -ge "$next" ] || exit 0
exec /usr/local/opnsense/scripts/OPNsense/Layer7Security/webexpire.php
