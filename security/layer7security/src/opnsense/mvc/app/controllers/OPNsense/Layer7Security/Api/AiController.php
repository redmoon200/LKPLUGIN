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
 * AI Service: one-click allow, watch or block per AI service. Rules that apply to
 * everybody all day are managed here; rules for groups or hours stay in the rules grid.
 */
class AiController extends ApiMutableModelControllerBase
{
    use \OPNsense\Layer7Security\LicenseGate;

    protected static $internalModelName = 'layer7security';
    protected static $internalModelClass = '\OPNsense\Layer7Security\Layer7Security';

    private function isGlobal($row)
    {
        return trim((string)$row->sources) === '' && trim((string)$row->users) === '' && (string)$row->startTime === (string)$row->endTime;
    }

    /** the catalog with the current simple rule of every service */
    public function stateAction()
    {
        $g = PolicyCompiler::general();
        $rules = [];
        foreach ($this->getModel()->ai->service->iterateItems() as $row) {
            if ((string)$row->enabled === '1' && $this->isGlobal($row)) {
                $rules[(string)$row->service] = ['action' => (string)$row->action, 'inspect' => (string)$row->inspect === '1'];
            }
        }
        $out = [];
        foreach (PolicyCompiler::aiCatalog() as $id => $svc) {
            $out[] = ['id' => $id, 'name' => $svc['name'], 'domains' => $svc['domains'] ?? [],
                      'action' => $rules[$id]['action'] ?? '', 'inspect' => $rules[$id]['inspect'] ?? false];
        }
        usort($out, function ($a, $b) {
            return strcasecmp($a['name'], $b['name']);
        });
        return ['services' => $out, 'default' => $g['aiDefault'], 'enabled' => $g['aiEnabled'], 'quic' => $g['aiQuic']];
    }

    /** POST services={"claude":{"action":"block","inspect":false}, ...}; action "" removes the simple rule */
    public function saveAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $in = $this->request->getPost('services');
        $in = is_array($in) ? $in : (json_decode((string)$in, true) ?: []);
        $catalog = PolicyCompiler::aiCatalog();
        Config::getInstance()->lock();
        $mdl = $this->getModel();
        $existing = [];
        foreach ($mdl->ai->service->iterateItems() as $uuid => $row) {
            if ($this->isGlobal($row)) {
                $existing[(string)$row->service] = $uuid;
            }
        }
        $changes = 0;
        foreach ($in as $id => $want) {
            if (!isset($catalog[$id]) || !is_array($want)) {
                continue;
            }
            $action = (string)($want['action'] ?? '');
            $inspect = !empty($want['inspect']) && $action !== 'block' ? '1' : '0';
            if (!in_array($action, ['allow', 'monitor', 'block'], true)) {
                if (isset($existing[$id])) {
                    $mdl->ai->service->del($existing[$id]);
                    $changes++;
                }
                continue;
            }
            if (isset($existing[$id])) {
                $node = $mdl->getNodeByReference('ai.service.' . $existing[$id]);
                $node->enabled = '1';
                $node->action = $action;
                $node->inspect = $inspect;
            } else {
                $node = $mdl->ai->service->Add();
                $node->setNodes(['enabled' => '1', 'service' => $id, 'action' => $action, 'inspect' => $inspect,
                    'description' => 'created by AI Service']);
            }
            $changes++;
        }
        $result = $this->validate();
        if (!empty($result['validations'])) {
            return ['result' => 'failed', 'validations' => $result['validations']];
        }
        $this->save(false, true);
        return ['result' => 'saved', 'changes' => $changes];
    }
}
