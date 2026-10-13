<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/** web download protection: detections, hash feed and a hash lookup */
class AntivirusController extends ApiControllerBase
{
    private function json($action, $params = [])
    {
        $be = new Backend();
        $out = $params ? $be->configdpRun($action, $params) : $be->configdRun($action);
        $data = json_decode(trim($out), true);
        return is_array($data) ? $data : [];
    }

    public function statusAction()
    {
        $status = $this->json('layer7security av-status');
        $status['proxy'] = trim((new Backend())->configdRun('layer7security proxy-status'));
        $status['running'] = strpos($status['proxy'], 'is running') !== false;
        $stats = json_decode(@file_get_contents('/var/run/layer7security/icap_stats.json'), true);
        $status['icapStats'] = is_array($stats) ? $stats : [];
        return $status;
    }

    public function searchAction()
    {
        $current = max(1, (int)$this->request->getPost('current', 'int', 1));
        $rows = (int)$this->request->getPost('rowCount', 'int', 25);
        $rows = ($rows < 1 || $rows > 500) ? 25 : $rows;
        $phrase = substr(trim(preg_replace('/[^A-Za-z0-9._:\/@ -]/', '', (string)$this->request->getPost('searchPhrase', 'string', ''))), 0, 64);
        $period = (int)$this->request->getPost('period', 'int', 86400);
        if (!in_array($period, [300, 3600, 21600, 86400, 604800, 2592000, 31536000], true)) {
            $period = 86400;
        }
        $data = $this->json('layer7security av-list', [$rows, ($current - 1) * $rows, $period, $phrase === '' ? '-' : $phrase]);
        if (!isset($data['rows'])) {
            return ['rows' => [], 'rowCount' => 0, 'total' => 0, 'current' => $current];
        }
        $data['current'] = $current;
        return $data;
    }

    public function feedUpdateAction()
    {
        if (!$this->request->isPost()) {
            return ['updated' => false, 'error' => 'POST required'];
        }
        return $this->json('layer7security av-feed-update');
    }

    public function checkAction()
    {
        if (!$this->request->isPost()) {
            return ['error' => 'POST required'];
        }
        $hash = strtolower(trim((string)$this->request->getPost('sha256', null, '')));
        if (!preg_match('/^[0-9a-f]{64}$/', $hash)) {
            return ['error' => 'A SHA-256 hash has 64 hexadecimal characters.'];
        }
        return $this->json('layer7security av-check', [$hash]);
    }
}
