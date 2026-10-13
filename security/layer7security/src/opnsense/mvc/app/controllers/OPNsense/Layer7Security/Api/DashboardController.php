<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Layer7Security\Layer7Security;
use OPNsense\Layer7Security\PolicyCompiler;

class DashboardController extends ApiControllerBase
{
    private function period()
    {
        $p = (int)$this->request->get('period', 'int', 3600);
        return in_array($p, [300, 3600, 21600, 86400, 604800], true) ? $p : 3600;
    }

    private function query($what)
    {
        $out = (new Backend())->configdpRun('layer7security stats', [$what, $this->period()]);
        $data = json_decode(trim($out), true);
        return is_array($data) ? $data : ['error' => 'no data'];
    }

    public function summaryAction()
    {
        return $this->query('summary');
    }

    public function appsAction()
    {
        return $this->query('apps');
    }

    public function categoriesAction()
    {
        return $this->query('categories');
    }

    public function clientsAction()
    {
        return $this->query('clients');
    }

    public function timelineAction()
    {
        return $this->query('timeline');
    }

    public function blocksAction()
    {
        return $this->query('blocks');
    }

    public function countriesAction()
    {
        return $this->query('countries');
    }

    public function aiAction()
    {
        return $this->query('ai');
    }

    public function devicesAction()
    {
        return $this->query('devices');
    }

    public function engineAction()
    {
        $data = json_decode(trim((new Backend())->configdRun('layer7security engine-status')), true);
        return is_array($data) ? $data : ['running' => false];
    }

    /** one line per module for the overview: on or off and a short detail */
    public function modulesAction()
    {
        $g = PolicyCompiler::general();
        $mdl = new Layer7Security();
        $web = PolicyCompiler::webRules();
        $app = 0;
        foreach ($mdl->policies->policy->iterateItems() as $p) {
            if ((string)$p->enabled === '1' && (string)$p->module !== 'cfs') {
                $app++;
            }
        }
        $ai = 0;
        foreach ($mdl->ai->service->iterateItems() as $r) {
            $ai += (string)$r->enabled === '1' ? 1 : 0;
        }
        $mods = [
            'web' => ['on' => $g['enabled'] && $g['webEnabled'] && count($web) > 0, 'detail' => count($web) . ' rules', 'url' => '/ui/layer7security/webcontrol'],
            'app' => ['on' => $g['enabled'] && $app > 0, 'detail' => $app . ' rules', 'url' => '/ui/layer7security/appcontrol'],
            'cfs' => ['on' => $g['enabled'] && $g['dnsFilter'], 'detail' => count($g['dnsCategories']) . ' categories', 'url' => '/ui/layer7security/cfs'],
            'dpi' => ['on' => $g['enabled'] && $g['dpiAllowed'], 'detail' => $g['dpiAll'] ? 'all HTTPS' : 'listed sites', 'url' => '/ui/layer7security/dpissl'],
            'av' => ['on' => $g['enabled'] && $g['avEnabled'], 'detail' => $g['avEnabled'] ? 'signatures ' . (string)$mdl->av->yaraAction : 'off', 'url' => '/ui/layer7security/antivirus'],
            'ai' => ['on' => $g['enabled'] && $g['aiEnabled'], 'detail' => $ai . ' service rules', 'url' => '/ui/layer7security/ai'],
            'inspect' => ['on' => $g['enabled'] && $g['inspectionAllowed'], 'detail' => $g['dlpEnabled'] ? 'detectors on' : 'off', 'url' => '/ui/layer7security/inspection'],
            'audit' => ['on' => $g['enabled'] && $g['auditEnabled'], 'detail' => $g['privacyAck'] ? 'notice acknowledged' : 'notice missing', 'url' => '/ui/layer7security/audit'],
            'auth' => ['on' => $g['enabled'] && $g['authEnabled'] && is_file('/var/db/layer7security/auth_ready'), 'detail' => $g['authEnabled'] ? 'sign-in required' : 'off', 'url' => '/ui/layer7security/access'],
        ];
        return ['modules' => $mods, 'enabled' => $g['enabled']];
    }
}
