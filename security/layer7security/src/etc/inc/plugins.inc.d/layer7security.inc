<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\Firewall\Plugin;
use OPNsense\Layer7Security\Layer7Security;
use OPNsense\Layer7Security\PolicyCompiler;

function layer7security_enabled()
{
    return (string)(new Layer7Security())->general->enabled === '1';
}

function layer7security_services()
{
    $services = [];

    if (!layer7security_enabled()) {
        return $services;
    }

    $services[] = [
        'description' => gettext('Layer 7 Security engine'),
        'pidfile' => '/var/run/layer7security.pid',
        'configd' => [
            'restart' => ['layer7security restart'],
            'start' => ['layer7security start'],
            'stop' => ['layer7security stop'],
        ],
        'name' => 'layer7security',
    ];

    return $services;
}

/**
 * Declare one persistent pf table per block policy (the engine fills them)
 * and the quick block rules that use them. Rules are per source network
 * because pf accepts a single address/network for "from" here.
 */
function layer7security_firewall(Plugin $fw)
{
    if (!layer7security_enabled()) {
        mwexecf('/sbin/pfctl -q -a l7sec_ether -f /dev/null', [], true);
        return;
    }
    $general = PolicyCompiler::general();
    layer7security_mac_anchor($fw, $general);
    layer7security_geo_rules($fw, $general);
    foreach (PolicyCompiler::policies() as $policy) {
        if ($policy['action'] !== 'block') {
            continue;
        }
        $fw->registerTable($policy['table'], true);
        $base = [
            'type' => 'block',
            'direction' => 'in',
            'quick' => true,
            'to' => '<' . $policy['table'] . '>',
            'descr' => 'Layer7 policy: ' . $policy['name'],
        ];
        if (!empty($policy['sources'])) {
            foreach ($policy['sources'] as $src) {
                $fw->registerFilterRule(2, array_merge($base, ['from' => $src]));
            }
        } elseif (!empty($policy['ifids'])) {
            foreach ($policy['ifids'] as $ifid) {
                $fw->registerFilterRule(2, array_merge($base, ['interface' => $ifid]));
            }
        } else {
            $fw->registerFilterRule(2, $base);
        }
    }
}

/**
 * pf "ether" rules (MAC binding) cannot be emitted through the plugin API, so
 * they live in their own anchor. The ruleset only needs a reference to it, and
 * it must sit before scrub/NAT. Table declarations are printed ahead of those
 * sections, so a table name carrying the anchor line puts the reference at a
 * legal position. Only fixed strings from this file are ever used here.
 */
function layer7security_mac_anchor(Plugin $fw, array $general)
{
    $anchor = 'l7sec_ether';
    $rules = PolicyCompiler::macRules($general, PolicyCompiler::bindings());
    $file = '/usr/local/etc/layer7security/mac.rules';
    if ($rules === '') {
        /* nothing to enforce: empty the anchor, no reference in the ruleset */
        mwexecf('/sbin/pfctl -q -a %s -f /dev/null', [$anchor], true);
        return;
    }
    if (!is_dir(dirname($file))) {
        mkdir(dirname($file), 0755, true);
    }
    file_put_contents($file, $rules);
    mwexecf('/sbin/pfctl -q -a %s -f %s', [$anchor, $file], true);
    $fw->registerTable('l7sec_ref_a> persist' . PHP_EOL . 'ether anchor "' . $anchor . '"' . PHP_EOL . 'table <l7sec_ref_b', false);
}

/** GeoIP: one table per policy (file written by geo_build.py) and block rules */
function layer7security_geo_rules(Plugin $fw, array $general)
{
    if (!$general['geoEnabled']) {
        return;
    }
    $ready = PolicyCompiler::geoDataReady();
    foreach (PolicyCompiler::geoPolicies() as $gp) {
        if (!is_file($gp['file'])) {
            @mkdir(dirname($gp['file']), 0750, true);
            touch($gp['file']);
        }
        /* "allow only" with no database would cut off everything: fail open */
        if ($gp['action'] === 'allow' && (!$ready || filesize($gp['file']) == 0)) {
            continue;
        }
        $fw->registerTable($gp['table'], true, $gp['file']);
        $not = $gp['action'] === 'allow';
        $dirs = $gp['direction'] === 'both' ? ['in', 'out'] : [$gp['direction']];
        foreach ($dirs as $dir) {
            $base = [
                'type' => 'block',
                'quick' => true,
                'log' => $gp['log'],
                'label' => 'l7geo_' . $gp['id'] . '_' . $dir,
                'descr' => 'Layer7 geo: ' . $gp['name'] . ' (' . $dir . ')',
            ];
            if ($dir === 'in') {
                /* traffic arriving from the country */
                $base['direction'] = 'in';
                $base['from'] = '<' . $gp['table'] . '>';
                $base['from_not'] = $not;
            } elseif (!empty($gp['ifids'])) {
                /* clients on the selected interfaces talking to the country */
                $base['direction'] = 'in';
                $base['to'] = '<' . $gp['table'] . '>';
                $base['to_not'] = $not;
            } else {
                $base['direction'] = 'out';
                $base['to'] = '<' . $gp['table'] . '>';
                $base['to_not'] = $not;
            }
            if (!empty($gp['ifids'])) {
                foreach ($gp['ifids'] as $ifid) {
                    $fw->registerFilterRule(1, array_merge($base, ['interface' => $ifid]));
                }
            } else {
                $fw->registerFilterRule(1, $base);
            }
        }
    }
}

function layer7security_cron()
{
    /* re-evaluate schedule windows for DNS filtering once a minute */
    return [
        ['autocron' => ['/usr/local/sbin/configctl -d layer7security dns-schedule', '*']],
        ['autocron' => ['/usr/local/sbin/configctl -d layer7security feed-update-auto', '17', '*/6']],
        ['autocron' => ['/usr/local/sbin/configctl -d layer7security geo-update-auto', '41', '4', '*', '*', '1']],
    ];
}
