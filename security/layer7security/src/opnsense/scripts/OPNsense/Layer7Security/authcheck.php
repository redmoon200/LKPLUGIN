#!/usr/local/bin/php
<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Password check for the sign-in portal. Reads one JSON document from stdin
 * ({"server": "...", "user": "...", "pass": "...", "groups": [...]}), asks the
 * OPNsense authentication server, and prints {"ok": true|false, "error": ...}.
 * The password never appears on a command line.
 */

require_once('script/load_phalcon.php');

use OPNsense\Auth\AuthenticationFactory;

$in = json_decode((string)stream_get_contents(STDIN, 8192), true);
if (!is_array($in) || !isset($in['user'], $in['pass'])) {
    echo json_encode(['ok' => false, 'error' => 'input']), "\n";
    exit(0);
}
$server = (new AuthenticationFactory())->get((string)($in['server'] ?? 'Local Database'));
if ($server === null) {
    echo json_encode(['ok' => false, 'error' => 'server']), "\n";
    exit(0);
}
$user = (string)$in['user'];
$ok = $server->authenticate($user, (string)$in['pass']);
if ($ok && !empty($in['groups'])) {
    $allowed = false;
    foreach ($in['groups'] as $group) {
        if ($server->groupAllowed($user, (string)$group)) {
            $allowed = true;
            break;
        }
    }
    if (!$allowed) {
        echo json_encode(['ok' => false, 'error' => 'group']), "\n";
        exit(0);
    }
}
echo json_encode(['ok' => (bool)$ok]), "\n";
