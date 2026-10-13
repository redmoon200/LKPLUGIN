<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/** antivirus for downloads: detections, hash and signature data, a hash lookup and a file scan */
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

    /** download hashes and signatures from the cloud server, and the optional extra hash list */
    public function feedUpdateAction()
    {
        if (!$this->request->isPost()) {
            return ['updated' => false, 'error' => 'POST required'];
        }
        $be = new Backend();
        $cloud = json_decode(trim($be->configdpRun('layer7security feed-update-parts', ['hashes,signatures'])), true);
        $own = $this->json('layer7security av-feed-update');
        $out = $own;
        $out['cloud'] = is_array($cloud) ? $cloud : [];
        $cloudOk = is_array($cloud) && ($cloud['result'] ?? '') === 'ok' && (!empty($cloud['hashes']) || !empty($cloud['signatures']));
        $out['updated'] = !empty($own['updated']) || $cloudOk;
        if (!$out['updated'] && empty($out['error']) && is_array($cloud) && ($cloud['result'] ?? '') === 'skipped') {
            $out['error'] = 'No cloud server address is set (Protection > CFS > Settings) and no extra hash list is configured.';
        }
        return $out;
    }

    public function checkAction()
    {
        if (!$this->request->isPost()) {
            return ['error' => 'POST required'];
        }
        $hash = strtolower(trim((string)$this->request->getPost('hash', null, $this->request->getPost('sha256', null, ''))));
        if (!preg_match('/^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/', $hash)) {
            return ['error' => 'Enter an MD5 (32), SHA-1 (40) or SHA-256 (64) hash in hexadecimal.'];
        }
        return $this->json('layer7security av-check', [$hash]);
    }

    /** scan an uploaded file with the same checks downloads get (nothing is kept) */
    public function scanFileAction()
    {
        if (!$this->request->isPost()) {
            return ['error' => 'POST required'];
        }
        try {
            return $this->scanUpload();
        } catch (\Throwable $e) {
            return ['error' => 'The scan could not run: ' . $e->getMessage()];
        }
    }

    private function scanUpload()
    {
        $up = $_FILES['file'] ?? null;
        if (!is_array($up) || ($up['error'] ?? 1) !== UPLOAD_ERR_OK || !is_uploaded_file((string)$up['tmp_name'])) {
            return ['error' => 'No file was received.'];
        }
        if ((int)$up['size'] > 25 * 1024 * 1024) {
            return ['error' => 'The file is larger than 25 MB.'];
        }
        $dir = '/var/db/layer7security/av/tmp';
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        $path = $dir . '/up.' . bin2hex(random_bytes(8));
        if (!move_uploaded_file((string)$up['tmp_name'], $path)) {
            return ['error' => 'The file could not be read.'];
        }
        chmod($path, 0600);
        $name = preg_replace('/[^A-Za-z0-9._-]/', '_', substr((string)$up['name'], 0, 80));
        $out = $this->json('layer7security av-scan-file', [$path, $name === '' ? 'file' : $name]);
        @unlink($path);
        return $out ?: ['error' => 'The scan failed.'];
    }
}
