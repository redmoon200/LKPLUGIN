<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

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
}
