<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class FlowsController extends ApiControllerBase
{
    /** bootgrid compatible search over stored flows */
    public function searchAction()
    {
        $current = max(1, (int)$this->request->getPost('current', 'int', 1));
        $rows = (int)$this->request->getPost('rowCount', 'int', 25);
        $rows = ($rows < 1 || $rows > 500) ? 25 : $rows;
        $phrase = preg_replace('/[^A-Za-z0-9._:\/ -]/', '', (string)$this->request->getPost('searchPhrase', 'string', ''));
        $phrase = substr(trim($phrase), 0, 64);
        $only = $this->request->getPost('only', 'string', '') === 'blocked' ? 'blocked' : 'all';
        $period = (int)$this->request->getPost('period', 'int', 86400);
        $period = in_array($period, [300, 3600, 21600, 86400, 604800], true) ? $period : 86400;
        $out = (new Backend())->configdpRun('layer7security flows', [
            $rows, ($current - 1) * $rows, $period, $only, $phrase === '' ? '-' : $phrase
        ]);
        $data = json_decode(trim($out), true);
        if (!is_array($data) || !isset($data['rows'])) {
            return ['rows' => [], 'rowCount' => 0, 'total' => 0, 'current' => $current];
        }
        $data['rowCount'] = count($data['rows']);
        $data['current'] = $current;
        return $data;
    }

    public function eventsAction()
    {
        $out = (new Backend())->configdpRun('layer7security events', [100]);
        $data = json_decode(trim($out), true);
        return ['events' => is_array($data) ? $data : []];
    }
}
