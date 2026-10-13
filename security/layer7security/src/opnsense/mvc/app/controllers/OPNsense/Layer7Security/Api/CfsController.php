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

/** Content filtering (CFS): website categories, safe search, threat lists and what the cloud provides */
class CfsController extends ApiControllerBase
{
    private function json($out, $default = [])
    {
        $data = json_decode(trim($out), true);
        return is_array($data) ? $data : $default;
    }

    /** what is installed (category lists, threat lists, hashes, signatures) and the filter state */
    public function statusAction()
    {
        $b = new Backend();
        $st = $this->json($b->configdRun('layer7security dns-status'));
        $g = PolicyCompiler::general();
        $st['enabled'] = $g['enabled'] && $g['dnsFilter'];
        $st['categories'] = $g['dnsCategories'];
        $st['safeSearch'] = $g['safeSearch'];
        $st['youtube'] = $g['youtubeMode'];
        $st['threatIps'] = $g['threatIps'];
        $st['mode'] = $g['dnsMode'];
        $st['unbound'] = file_exists('/usr/local/etc/unbound.opnsense.d/layer7security.conf');
        return $st;
    }

    /** download from the cloud server: ?parts=domains,ips,hashes,signatures (default all) */
    public function updateAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $parts = preg_replace('/[^a-z,]/', '', (string)$this->request->getPost('parts', 'string', ''));
        $parts = $parts === '' ? 'domains,ips,hashes,signatures' : $parts;
        return $this->json((new Backend())->configdpRun('layer7security feed-update-parts', [$parts]), ['result' => 'failed']);
    }

    /** which categories list a website */
    public function lookupAction()
    {
        $q = (string)$this->request->getPost('q', 'string', $this->request->get('q', 'string', ''));
        $q = substr(preg_replace('/[^A-Za-z0-9.:\/_-]/', '', $q), 0, 200);
        if ($q === '') {
            return ['error' => 'enter a website'];
        }
        return $this->json((new Backend())->configdpRun('layer7security cfs-lookup', [$q]), ['error' => 'no answer']);
    }

    /** lookups the DNS filter answered itself: ?module=cfs|web|all&minutes=1440&limit=200 */
    public function logAction()
    {
        $module = (string)$this->request->get('module', 'string', 'cfs');
        $module = in_array($module, ['cfs', 'web', 'all'], true) ? $module : 'cfs';
        $minutes = max(1, min(10080, (int)$this->request->get('minutes', 'int', 1440)));
        $limit = max(1, min(500, (int)$this->request->get('limit', 'int', 200)));
        return $this->json((new Backend())->configdpRun('layer7security cfs-log', [$module, $minutes, $limit]), ['rows' => []]);
    }
}
