#!/usr/local/bin/php
<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Remove Web Control rules whose time has run out and apply the configuration.
 */

require_once('script/load_phalcon.php');

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Layer7Security\Layer7Security;

$mdl = new Layer7Security();
$gone = [];
foreach ($mdl->webcontrol->rule->iterateItems() as $uuid => $r) {
    $exp = (int)(string)$r->expires;
    if ($exp > 0 && $exp <= time()) {
        $gone[] = $uuid;
    }
}
if (!empty($gone)) {
    Config::getInstance()->lock();
    $mdl = new Layer7Security();
    foreach ($gone as $uuid) {
        $mdl->webcontrol->rule->del($uuid);
    }
    $mdl->serializeToConfig(false, true);
    Config::getInstance()->save(['description' => 'Layer 7 Security: temporary Web Control rules expired']);
    (new Backend())->configdRun('layer7security apply');
}
