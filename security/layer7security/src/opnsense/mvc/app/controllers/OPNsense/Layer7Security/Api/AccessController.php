<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Layer7Security\PolicyCompiler;

/** Users and Access: who is signed in to the web access portal, and its log */
class AccessController extends ApiControllerBase
{
    private function json($out, $default)
    {
        $data = json_decode(trim($out), true);
        return is_array($data) ? $data : $default;
    }

    public function statusAction()
    {
        $b = new Backend();
        $general = PolicyCompiler::general();
        $portal = PolicyCompiler::portal($general);
        $st = $this->json($b->configdRun('layer7security auth-status'), []);
        $st['enabled'] = $portal !== null;
        $st['configured'] = $general['authEnabled'];
        $st['running'] = strpos(trim($b->configdRun('layer7security portal-status')), 'is running') !== false;
        $st['ready'] = is_file('/var/db/layer7security/auth_ready');
        return $st;
    }

    public function sessionsAction()
    {
        return $this->json((new Backend())->configdRun('layer7security auth-sessions'), ['rows' => []]);
    }

    public function logoutAction()
    {
        if (!$this->request->isPost()) {
            return ['ok' => false];
        }
        $ip = (string)$this->request->getPost('ip', 'string', '');
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return ['ok' => false, 'message' => 'not an IP address'];
        }
        return $this->json((new Backend())->configdpRun('layer7security auth-logout', [$ip]), ['ok' => false]);
    }

    public function logoutAllAction()
    {
        if (!$this->request->isPost()) {
            return ['ok' => false];
        }
        return $this->json((new Backend())->configdRun('layer7security auth-logout-all'), ['ok' => false]);
    }

    public function logAction()
    {
        $rows = max(1, min(500, (int)$this->request->get('rows', 'int', 100)));
        return $this->json((new Backend())->configdpRun('layer7security auth-log', [$rows]), ['rows' => []]);
    }
}
