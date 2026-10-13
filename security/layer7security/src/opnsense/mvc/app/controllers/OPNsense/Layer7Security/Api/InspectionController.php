<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/** TLS inspection: CA handling, proxy status and a detector test box */
class InspectionController extends ApiControllerBase
{
    private function user()
    {
        return preg_replace('/[^A-Za-z0-9_.@-]/', '', (string)$this->getUserName()) ?: 'unknown';
    }

    private function json($action, $params = [])
    {
        $be = new Backend();
        $out = $params ? $be->configdpRun($action, $params) : $be->configdRun($action);
        $data = json_decode(trim($out), true);
        return is_array($data) ? $data : [];
    }

    public function statusAction()
    {
        $status = $this->json('layer7security inspection-status');
        $status['proxy'] = trim((new Backend())->configdRun('layer7security proxy-status'));
        $status['running'] = strpos($status['proxy'], 'is running') !== false;
        return $status;
    }

    public function caInfoAction()
    {
        return $this->json('layer7security inspection-ca-info');
    }

    /** the CA certificate to install on the clients (the key never leaves the firewall) */
    public function caAction()
    {
        $pem = (new Backend())->configdRun('layer7security inspection-ca-pem');
        if (strpos($pem, 'BEGIN CERTIFICATE') === false) {
            $this->response->setStatusCode(404, 'Not Found');
            $this->response->setContentType('text/plain', 'UTF-8');
            $this->response->setContent('The inspection CA has not been created yet. Enable AI content inspection and apply first.');
            return;
        }
        $this->response->setContentType('application/x-x509-ca-cert', 'UTF-8');
        $this->response->setHeader('Content-Disposition', 'attachment; filename="layer7-inspection-ca.crt"');
        $this->response->setHeader('X-Content-Type-Options', 'nosniff');
        $this->response->setContent($pem);
    }

    /** replace the CA: every client must trust the new certificate afterwards */
    public function caNewAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $res = $this->json('layer7security inspection-ca-new');
        (new Backend())->configdpRun('layer7security audit-access', [$this->user(), 'ca-regenerate']);
        if (!empty($res['created'])) {
            (new Backend())->configdRun('layer7security apply');
        }
        return $res;
    }

    /** run the detectors over pasted text; nothing is stored or logged */
    public function testAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $text = substr((string)$this->request->getPost('text', null, ''), 0, 65536);
        if ($text === '') {
            return ['detections' => [], 'masked' => ''];
        }
        $path = '/tmp/l7test.' . bin2hex(random_bytes(8));
        $old = umask(0077);
        file_put_contents($path, $text);
        umask($old);
        $res = $this->json('layer7security inspection-test', [$path]);
        @unlink($path);
        return $res;
    }
}
