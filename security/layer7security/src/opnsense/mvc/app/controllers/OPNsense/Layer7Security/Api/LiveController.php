<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Live session console: the connections open right now, enriched with what
 * the engine knows. Quick actions (block or allow a site or address) are in
 * the Web Control API (webcontrol/quick).
 */
class LiveController extends ApiControllerBase
{
    use \OPNsense\Layer7Security\LicenseGate;

    /** open connections: ?limit=200&q=text&dir=out,in,internal */
    public function sessionsAction()
    {
        $limit = max(1, min(600, (int)$this->request->get('limit', 'int', 200)));
        $q = preg_replace('/[^A-Za-z0-9._:\/ -]/', '', (string)$this->request->get('q', 'string', ''));
        $q = substr(trim($q), 0, 64);
        $dir = (string)$this->request->get('dir', 'string', 'all');
        if ($dir !== 'all' && !preg_match('/^(out|in|internal|firewall|other)(,(out|in|internal|firewall|other))*$/', $dir)) {
            $dir = 'all';
        }
        $out = (new Backend())->configdpRun('layer7security live-sessions', [$limit, $q === '' ? '-' : $q, $dir]);
        $data = json_decode(trim($out), true);
        return is_array($data) ? $data : ['rows' => [], 'error' => 'no data'];
    }

    /** blocks and detections of the last minutes */
    public function recentAction()
    {
        $minutes = max(1, min(1440, (int)$this->request->get('minutes', 'int', 10)));
        $out = (new Backend())->configdpRun('layer7security live-recent', [$minutes]);
        $data = json_decode(trim($out), true);
        return is_array($data) ? $data : ['rows' => []];
    }

    /** events of one module: ?module=web|app|ai&minutes=1440&limit=200 */
    public function eventsAction()
    {
        $module = (string)$this->request->get('module', 'string', 'all');
        $module = in_array($module, ['web', 'app', 'ai', 'all'], true) ? $module : 'all';
        $minutes = max(1, min(10080, (int)$this->request->get('minutes', 'int', 1440)));
        $limit = max(1, min(500, (int)$this->request->get('limit', 'int', 200)));
        $out = (new Backend())->configdpRun('layer7security live-events', [$module, $minutes, $limit]);
        $data = json_decode(trim($out), true);
        return is_array($data) ? $data : ['rows' => []];
    }
}
