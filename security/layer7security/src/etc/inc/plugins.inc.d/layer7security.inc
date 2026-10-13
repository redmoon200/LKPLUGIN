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
    layer7security_webip_rules($fw, $general);
    layer7security_threat_rules($fw, $general);
    layer7security_ai_rules($fw, $general);
    layer7security_proxy_rules($fw, $general);
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

/**
 * Web Control IP rules: one table per group of client sources, filled from a
 * file written by apply.php ("!" entries are the allow exceptions).
 */
function layer7security_webip_rules(Plugin $fw, array $general)
{
    foreach (PolicyCompiler::webIpGroups($general) as $g) {
        if (!is_file($g['file'])) {
            continue;
        }
        $fw->registerTable($g['table'], true, $g['file']);
        $base = [
            'type' => 'block', 'direction' => 'in', 'quick' => true, 'to' => '<' . $g['table'] . '>',
            'label' => 'l7web_ip_' . $g['id'], 'descr' => 'Layer7 Web Control: blocked IP addresses',
        ];
        if (empty($g['sources'])) {
            $fw->registerFilterRule(1, $base);
            /* and nothing may come in from them either */
            $fw->registerFilterRule(1, [
                'type' => 'block', 'direction' => 'in', 'quick' => true, 'from' => '<' . $g['table'] . '>',
                'label' => 'l7web_ipin_' . $g['id'], 'descr' => 'Layer7 Web Control: blocked IP addresses (inbound)',
            ]);
        } else {
            foreach ($g['sources'] as $src) {
                $fw->registerFilterRule(1, array_merge($base, ['from' => $src]));
            }
        }
    }
}

/** known-bad address lists (botnet servers, hijacked networks, ...) downloaded from the cloud server */
function layer7security_threat_rules(Plugin $fw, array $general)
{
    foreach (PolicyCompiler::threatLists($general) as $t) {
        if (!is_file($t['file'])) {
            continue;
        }
        $fw->registerTable($t['table'], true, $t['file']);
        $out = [
            'type' => 'block', 'direction' => 'in', 'quick' => true, 'to' => '<' . $t['table'] . '>',
            'label' => 'l7thr_' . $t['id'], 'descr' => 'Layer7 CFS: threat list ' . $t['id'],
        ];
        foreach ($general['ifids'] as $ifid) {
            $fw->registerFilterRule(1, array_merge($out, ['interface' => $ifid]));
        }
        if ($general['threatDirection'] === 'both') {
            $fw->registerFilterRule(1, [
                'type' => 'block', 'direction' => 'in', 'quick' => true, 'from' => '<' . $t['table'] . '>',
                'label' => 'l7thr_in_' . $t['id'], 'descr' => 'Layer7 CFS: threat list ' . $t['id'] . ' (inbound)',
            ]);
        }
    }
}

/**
 * AI services: tables the engine fills (inspection proxy redirect, QUIC block)
 * and the QUIC block rules. QUIC to AI services is dropped so clients fall back
 * to TCP/TLS, where the SNI is visible and the connection can be inspected.
 */
function layer7security_ai_rules(Plugin $fw, array $general)
{
    if (!$general['aiEnabled']) {
        return;
    }
    if ($general['aiQuic'] !== 'off') {
        $base = ['type' => 'block', 'quick' => true, 'direction' => 'in', 'protocol' => 'udp',
                 'to_port' => '443', 'label' => 'l7ai_quic', 'descr' => 'Layer7 AI: block QUIC'];
        if ($general['aiQuic'] === 'ai') {
            $fw->registerTable('l7_ai_quic', true);
            $base['to'] = '<l7_ai_quic>';
        }
        foreach ($general['ifids'] as $ifid) {
            $fw->registerFilterRule(1, array_merge($base, ['interface' => $ifid]));
        }
    }
}

/**
 * Transparent proxy: AI services selected for inspection (addresses learned by
 * the engine into <l7_ai_bump>) and, for web antivirus, plain HTTP are
 * redirected to the local Squid ports. Everything else is left alone.
 */
function layer7security_proxy_rules(Plugin $fw, array $general)
{
    $https = !empty($general['aiInspect']);
    $http = $general['avEnabled'] && $general['avHttp'];
    if (!$https && !$http) {
        return;
    }
    if ($https) {
        $fw->registerTable('l7_ai_bump', true);
    }
    foreach ($general['ifids'] as $ifid) {
        $ports = [];
        if ($https) {
            $ports[] = ['443', '3129', '<l7_ai_bump>'];
        }
        if ($http) {
            /* internal destinations are never sent through the antivirus proxy */
            $fw->registerForwardRule(2, [
                'interface' => $ifid, 'nordr' => true, 'ipprotocol' => 'inet', 'protocol' => 'tcp',
                'to' => '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16', 'to_port' => '80',
                'natreflection' => 'disable', 'descr' => 'Layer7 antivirus: no proxy for internal destinations',
            ]);
            $ports[] = ['80', '3128', 'any'];
        }
        foreach ($ports as [$dport, $lport, $to]) {
            $fw->registerForwardRule(2, [
                'interface' => $ifid, 'nordr' => false, 'ipprotocol' => 'inet', 'protocol' => 'tcp',
                'to' => $to, 'to_port' => $dport, 'target' => '127.0.0.1', 'localport' => $lport,
                'natreflection' => 'disable', 'descr' => 'Layer7: redirect to the inspection proxy',
            ]);
            $fw->registerFilterRule(2, [
                'type' => 'pass', 'interface' => $ifid, 'direction' => 'in', 'ipprotocol' => 'inet',
                'protocol' => 'tcp', 'to' => '127.0.0.1', 'to_port' => $lport, 'quick' => true,
                'descr' => 'Layer7: allow traffic redirected to the inspection proxy',
            ]);
        }
    }
}

function layer7security_cron()
{
    /* re-evaluate schedule windows for DNS filtering once a minute */
    return [
        ['autocron' => ['/usr/local/sbin/configctl -d layer7security dns-schedule', '*']],
        ['autocron' => ['/usr/local/sbin/configctl -d layer7security web-expire', '*']],
        ['autocron' => ['/usr/local/sbin/configctl -d layer7security feed-update-auto', '17', '*/6']],
        ['autocron' => ['/usr/local/sbin/configctl -d layer7security geo-update-auto', '41', '4', '*', '*', '1']],
        ['autocron' => ['/usr/local/sbin/configctl -d layer7security audit-ingest', '*']],
        ['autocron' => ['/usr/local/sbin/configctl -d layer7security audit-prune', '23', '3']],
        ['autocron' => ['/usr/local/sbin/configctl -d layer7security av-feed-auto', '11', '*/3']],
        ['autocron' => ['/usr/local/sbin/configctl -d layer7security av-prune', '37', '3']],
    ];
}
