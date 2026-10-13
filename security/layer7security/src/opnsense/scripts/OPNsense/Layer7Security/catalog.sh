#!/bin/sh

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Rebuild the application and category catalog used by the GUI selectors from
# the nDPI library the engine is linked against.

ENGINE=/usr/local/libexec/layer7security/l7engine
DIR=/usr/local/etc/layer7security

if [ ! -x "${ENGINE}" ]; then
	echo "engine binary missing"
	exit 1
fi

mkdir -p "${DIR}"
"${ENGINE}" --list-apps > "${DIR}/apps.json.tmp" && mv "${DIR}/apps.json.tmp" "${DIR}/apps.json" || exit 1
"${ENGINE}" --list-categories > "${DIR}/categories.json.tmp" && mv "${DIR}/categories.json.tmp" "${DIR}/categories.json" || exit 1
echo "OK"
