#!/usr/local/bin/php
<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * License helper for cron and the downloaders.
 *
 *   license.php status             JSON state of the license
 *   license.php check              refresh the state; when it switched between valid and locked, apply
 *   license.php activate KEY       store a key
 *   license.php revoked KEYID 1|0  the vendor's server withdrew or reinstated the key
 *   license.php resetseen          the vendor's server confirmed the clock: forget a last-seen time in the future
 */

require_once('script/load_phalcon.php');

use OPNsense\Core\Backend;
use OPNsense\Layer7Security\License;

const APPLIED = '/var/db/layer7security/license_applied';

function applyIfChanged()
{
    $now = License::status(true)['valid'] ? 'valid' : 'locked';
    $before = trim((string)@file_get_contents(APPLIED));
    if ($before !== $now) {
        (new Backend())->configdRun('layer7security apply');
        return true;
    }
    return false;
}

$cmd = $argv[1] ?? 'status';
switch ($cmd) {
    case 'check':
        echo json_encode(['applied' => applyIfChanged(), 'status' => License::status()]), "\n";
        break;
    case 'activate':
        $key = (string)($argv[2] ?? '');
        $res = preg_match('/^[A-Za-z2-7-]{100,400}$/', $key) ? License::activate($key) : ['ok' => false, 'message' => 'That does not look like a license key.'];
        if (!empty($res['ok'])) {
            applyIfChanged();
        }
        echo json_encode($res), "\n";
        break;
    case 'revoked':
        $id = (string)($argv[2] ?? '');
        if (preg_match('/^[0-9A-F]{16}$/', $id)) {
            License::setRevoked($id, ($argv[3] ?? '1') === '1');
            applyIfChanged();
        }
        echo json_encode(License::status(true)), "\n";
        break;
    case 'resetseen':
        License::resetSeen();
        applyIfChanged();
        echo json_encode(License::status(true)), "\n";
        break;
    default:
        echo json_encode(License::status(true)), "\n";
}
