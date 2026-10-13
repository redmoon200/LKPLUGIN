<?php
/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Lab helper: add VLAN 10 on the LAN device (vlan0.10), assign it as opt1
 * with 10.88.0.1/24 and allow its clients to reach anywhere. Run on the
 * OPNsense VM:  php make-vlan.php  (then reboot or reload interfaces)
 */
require_once('script/load_phalcon.php');
use OPNsense\Core\Config;
use OPNsense\Interfaces\Vlan;

$vlans = new Vlan();
$exists = false;
foreach ($vlans->vlan->iterateItems() as $v) {
    if ((string)$v->vlanif === 'vlan0.10') {
        $exists = true;
    }
}
if (!$exists) {
    $n = $vlans->vlan->Add();
    $n->if = 'vtnet0';
    $n->tag = '10';
    $n->vlanif = 'vlan0.10';
    $n->descr = 'lab vlan 10';
    $vlans->serializeToConfig();
}
$cfg = Config::getInstance()->object();
if (!isset($cfg->interfaces->opt1)) {
    $o = $cfg->interfaces->addChild('opt1');
    $o->addChild('if', 'vlan0.10');
    $o->addChild('descr', 'VLAN10');
    $o->addChild('enable', '1');
    $o->addChild('ipaddr', '10.88.0.1');
    $o->addChild('subnet', '24');
    $r = $cfg->filter->addChild('rule');
    $r->addChild('type', 'pass');
    $r->addChild('interface', 'opt1');
    $r->addChild('ipprotocol', 'inet');
    $r->addChild('source')->addChild('network', 'opt1');
    $r->addChild('destination')->addChild('any');
    $r->addChild('descr', 'lab: VLAN10 to anywhere');
}
Config::getInstance()->save();
echo "vlan configured\n";
