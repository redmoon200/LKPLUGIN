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
        return;
    }
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

function layer7security_cron()
{
    /* re-evaluate schedule windows for DNS filtering once a minute */
    return [
        ['autocron' => ['/usr/local/sbin/configctl -d layer7security dns-schedule', '*']],
        ['autocron' => ['/usr/local/sbin/configctl -d layer7security feed-update-auto', '17', '*/6']],
    ];
}
