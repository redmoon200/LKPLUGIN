#!/usr/local/bin/php
<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The part of remote support that changes settings. It is only started by support.py after a
 * signed command was verified, and it checks everything again: nothing here trusts the caller.
 *
 *   support.php web_rule JSON       add, remove, enable or disable a Web Control rule
 *   support.php set_option JSON     change one option from a short allowlist
 *   support.php toggle_item JSON    switch an existing rule, user, binding or policy on or off
 *
 * Changes go through the plugin's model (the same validation as the GUI), are saved to the
 * configuration and applied. Prints one line of JSON.
 */

require_once('script/load_phalcon.php');

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Layer7Security\Layer7Security;
use OPNsense\Layer7Security\PolicyCompiler;

const OPTIONS = ['general.enabled', 'general.enforce', 'general.retention', 'general.flowTimeout', 'general.blockTtl', 'general.dnsFilter',
    'general.dnsMode', 'general.dnsCategories', 'general.dnsBlock', 'general.dnsAllow', 'general.geoEnabled', 'general.aiEnabled',
    'general.aiDefault', 'general.aiQuic', 'webcontrol.enabled', 'cfs.safeSearch', 'cfs.youtube', 'cfs.threatIps', 'cfs.threatDirection'];
const UUID = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/';

function done($ok, $message, $extra = [])
{
    echo json_encode(array_merge(['ok' => $ok, 'message' => $message], $extra)), "\n";
    exit($ok ? 0 : 1);
}

/** validate, save and apply; returns the message list when the model refuses */
function commit($mdl, $what)
{
    $errors = [];
    foreach ($mdl->performValidation() as $msg) {
        $errors[] = $msg->getField() . ': ' . $msg->getMessage();
    }
    if (!empty($errors)) {
        done(false, 'The setting was refused: ' . implode(' ', array_slice($errors, 0, 3)));
    }
    $mdl->serializeToConfig(false, true);
    Config::getInstance()->save(['description' => 'Layer 7 Security: remote support: ' . $what]);
    (new Backend())->configdRun('layer7security apply');
}

function container($mdl, $section)
{
    switch ($section) {
        case 'policies':
            return $mdl->policies->policy;
        case 'webcontrol':
            return $mdl->webcontrol->rule;
        case 'bindings':
            return $mdl->bindings->binding;
        case 'geo':
            return $mdl->geo->policy;
        case 'users':
            return $mdl->users->user;
    }
    return null;
}

$cmd = $argv[1] ?? '';
$p = json_decode($argv[2] ?? '{}', true);
if (!is_array($p)) {
    done(false, 'Bad parameters.');
}

Config::getInstance()->lock();
$mdl = new Layer7Security();

switch ($cmd) {
    case 'web_rule':
        $op = (string)($p['op'] ?? '');
        if ($op === 'add') {
            $kind = ($p['kind'] ?? '') === 'ip' ? 'ip' : 'domain';
            $action = ($p['rule_action'] ?? '') === 'allow' ? 'allow' : 'block';
            $value = $kind === 'ip' ? PolicyCompiler::normalizeIp((string)($p['value'] ?? '')) : PolicyCompiler::normalizeSite((string)($p['value'] ?? ''));
            if ($value === null) {
                done(false, 'That is not a valid ' . ($kind === 'ip' ? 'IP address' : 'website') . '.');
            }
            if ($kind === 'ip' && $action === 'block' && PolicyCompiler::coversFirewall($value)) {
                done(false, 'That address belongs to the firewall itself: blocking it would cut off the management access.');
            }
            $minutes = max(0, min(525600, (int)($p['minutes'] ?? 0)));
            $note = substr(preg_replace('/[^\x20-\x7e]/', '', (string)($p['note'] ?? '')), 0, 120);
            $note = trim('Remote support ' . $note);
            $now = time();
            $change = 'added';
            $node = null;
            foreach ($mdl->webcontrol->rule->iterateItems() as $uuid => $r) {
                if ((string)$r->kind !== $kind || strtolower((string)$r->value) !== $value || (string)$r->sources !== '') {
                    continue;
                }
                if ((string)$r->action === $action) {
                    $r->enabled = '1';
                    $r->expires = (string)($minutes > 0 ? $now + $minutes * 60 : 0);
                    $change = 'updated';
                    $node = $r;
                } else {
                    $mdl->webcontrol->rule->del($uuid);
                    $change = 'replaced';
                }
            }
            if ($node === null) {
                $node = $mdl->webcontrol->rule->Add();
                $node->setNodes(['enabled' => '1', 'kind' => $kind, 'value' => $value, 'action' => $action, 'sources' => '',
                    'expires' => (string)($minutes > 0 ? $now + $minutes * 60 : 0), 'origin' => 'support', 'created' => (string)$now, 'description' => $note]);
            }
            commit($mdl, "$action $value");
            done(true, ucfirst($action) . " rule for $value $change" . ($minutes > 0 ? " for $minutes minutes." : '.'), ['change' => $change]);
        }
        $uuid = (string)($p['uuid'] ?? '');
        if (!in_array($op, ['remove', 'enable', 'disable'], true) || !preg_match(UUID, $uuid)) {
            done(false, 'Choose a rule.');
        }
        $found = null;
        foreach ($mdl->webcontrol->rule->iterateItems() as $u => $r) {
            if ($u === $uuid) {
                $found = $r;
            }
        }
        if ($found === null) {
            done(false, 'That rule does not exist (any more).');
        }
        $label = (string)$found->action . ' ' . (string)$found->value;
        if ($op === 'remove') {
            $mdl->webcontrol->rule->del($uuid);
        } else {
            $found->enabled = $op === 'enable' ? '1' : '0';
        }
        commit($mdl, "$op rule $label");
        done(true, "Rule ($label) " . ($op === 'remove' ? 'removed.' : ($op === 'enable' ? 'switched on.' : 'switched off.')));

    case 'set_option':
        $path = (string)($p['path'] ?? '');
        $value = (string)($p['value'] ?? '');
        if (!in_array($path, OPTIONS, true)) {
            done(false, 'That option cannot be changed remotely.');
        }
        [$sec, $field] = explode('.', $path);
        $node = $mdl->$sec->$field;
        $old = (string)$node;
        $node->setValue($value);
        commit($mdl, "$path");
        done(true, "$path changed from '" . substr($old, 0, 80) . "' to '" . substr($value, 0, 80) . "'.");

    case 'toggle_item':
        $section = (string)($p['section'] ?? '');
        $uuid = (string)($p['uuid'] ?? '');
        $enabled = (string)($p['enabled'] ?? '') === '1' ? '1' : '0';
        $box = container($mdl, $section);
        if ($box === null || !preg_match(UUID, $uuid)) {
            done(false, 'Choose an item.');
        }
        $found = null;
        foreach ($box->iterateItems() as $u => $item) {
            if ($u === $uuid) {
                $found = $item;
            }
        }
        if ($found === null) {
            done(false, 'That item does not exist (any more).');
        }
        $found->enabled = $enabled;
        commit($mdl, "$section $uuid enabled=$enabled");
        done(true, ucfirst($section) . ' item switched ' . ($enabled === '1' ? 'on.' : 'off.'));
}

done(false, 'Unknown action.');
