<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\Layer7Security\PolicyCompiler;

/**
 * Application Control: one-click rules per application category or application.
 * They are ordinary policies named "AppControl: <name>"; the advanced rules
 * grid (full policies) lives in the Settings controller.
 */
class AppcontrolController extends ApiMutableModelControllerBase
{
    use \OPNsense\Layer7Security\LicenseGate;

    protected static $internalModelName = 'layer7security';
    protected static $internalModelClass = '\OPNsense\Layer7Security\Layer7Security';

    private const PREFIX = 'AppControl - ';
    /** categories offered as one-click switches */
    private const QUICK = ['SocialNetwork', 'Streaming', 'Video', 'Music', 'Game', 'Chat', 'VoIP', 'VPN', 'RemoteAccess',
        'FileSharing', 'Download', 'Cloud', 'Shopping', 'Gambling', 'AdultContent', 'Dating', 'Mining', 'Crypto_Currency'];

    private function catalog()
    {
        $apps = json_decode(@file_get_contents('/usr/local/etc/layer7security/apps.json') ?: '[]', true);
        return is_array($apps) ? $apps : [];
    }

    /** current one-click states: {categories: {name: action}, applications: {name: action}} */
    public function stateAction()
    {
        $cats = [];
        $apps = [];
        foreach ($this->getModel()->policies->policy->iterateItems() as $p) {
            $name = (string)$p->name;
            if (strpos($name, self::PREFIX) !== 0 || (string)$p->module !== 'app' || (string)$p->enabled !== '1') {
                continue;
            }
            $c = array_filter(explode(',', (string)$p->categories));
            $a = array_filter(explode(',', (string)$p->applications));
            if (count($c) === 1 && empty($a)) {
                $cats[reset($c)] = (string)$p->action;
            } elseif (count($a) === 1 && empty($c)) {
                $apps[reset($a)] = (string)$p->action;
            }
        }
        return ['categories' => $cats, 'applications' => $apps, 'quick' => self::QUICK];
    }

    /** search the catalog of applications that the engine recognises */
    public function searchAppsAction()
    {
        $q = strtolower(trim((string)$this->request->get('q', 'string', '')));
        $state = $this->stateAction()['applications'];
        $rows = [];
        $all = $this->catalog();
        foreach ($all as $a) {
            if (empty($a['name'])) {
                continue;
            }
            $hay = strtolower($a['name'] . ' ' . ($a['category'] ?? ''));
            if ($q !== '' && strpos($hay, $q) === false) {
                continue;
            }
            $rows[] = ['name' => $a['name'], 'category' => $a['category'] ?? '', 'action' => $state[$a['name']] ?? 'allow'];
            if (count($rows) >= 100) {
                break;
            }
        }
        return ['rows' => $rows, 'total' => count($all)];
    }

    /**
     * POST categories={"SocialNetwork":"block",...} and/or applications={"TikTok":"monitor"}.
     * "allow" removes the rule, "monitor" only records, "block" blocks for everybody.
     */
    public function saveAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $cats = $this->request->getPost('categories');
        $apps = $this->request->getPost('applications');
        $cats = is_array($cats) ? $cats : (json_decode((string)$cats, true) ?: []);
        $apps = is_array($apps) ? $apps : (json_decode((string)$apps, true) ?: []);
        $known = [];
        foreach ($this->catalog() as $a) {
            if (!empty($a['name'])) {
                $known[$a['name']] = true;
            }
        }
        Config::getInstance()->lock();
        $mdl = $this->getModel();
        $existing = [];
        foreach ($mdl->policies->policy->iterateItems() as $uuid => $p) {
            if (strpos((string)$p->name, self::PREFIX) === 0 && (string)$p->module === 'app') {
                $existing[(string)$p->name] = $uuid;
            }
        }
        $changes = 0;
        $seq = 900;
        $apply = function ($kind, $name, $action) use ($mdl, &$existing, &$changes, &$seq) {
            $action = in_array($action, ['allow', 'monitor', 'block'], true) ? $action : 'allow';
            $pname = self::PREFIX . $name;
            $seq++;
            if ($action === 'allow') {
                if (isset($existing[$pname])) {
                    $mdl->policies->policy->del($existing[$pname]);
                    $changes++;
                }
                return;
            }
            if (isset($existing[$pname])) {
                $node = $mdl->getNodeByReference('policies.policy.' . $existing[$pname]);
                if ((string)$node->action !== $action || (string)$node->enabled !== '1') {
                    $node->action = $action;
                    $node->enabled = '1';
                    $changes++;
                }
                return;
            }
            $node = $mdl->policies->policy->Add();
            $field = $kind === 'cat' ? 'categories' : 'applications';
            $node->setNodes([
                'enabled' => '1', 'name' => $pname, 'sequence' => (string)$seq, 'action' => $action, 'module' => 'app',
                $field => $name, 'description' => 'created by Application Control',
            ]);
            $changes++;
        };
        foreach ($cats as $name => $action) {
            if (in_array($name, self::QUICK, true)) {
                $apply('cat', $name, $action);
            }
        }
        foreach ($apps as $name => $action) {
            if (isset($known[$name])) {
                $apply('app', $name, $action);
            }
        }
        $result = $this->validate();
        if (!empty($result['validations'])) {
            return ['result' => 'failed', 'validations' => $result['validations']];
        }
        $this->save(false, true);
        return ['result' => 'saved', 'changes' => $changes];
    }

    public function statusAction()
    {
        $n = ['rules' => 0, 'block' => 0, 'monitor' => 0, 'quick' => 0];
        foreach ($this->getModel()->policies->policy->iterateItems() as $p) {
            if ((string)$p->module !== 'app' || (string)$p->enabled !== '1') {
                continue;
            }
            $n['rules']++;
            if ((string)$p->action === 'block') {
                $n['block']++;
            } elseif ((string)$p->action === 'monitor') {
                $n['monitor']++;
            }
            if (strpos((string)$p->name, self::PREFIX) === 0) {
                $n['quick']++;
            }
        }
        $g = PolicyCompiler::general();
        return ['enabled' => $g['enabled'], 'enforce' => $g['enforce'], 'counts' => $n];
    }
}
