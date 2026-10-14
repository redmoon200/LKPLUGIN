<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Layer7Security\License;

/** License: state, key entry, trial, and the cloud server connection (never locked itself) */
class LicenseController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'layer7security';
    protected static $internalModelClass = '\OPNsense\Layer7Security\Layer7Security';

    private function json($action, $params = [])
    {
        $be = new Backend();
        $out = $params ? $be->configdpRun('layer7security ' . $action, $params) : $be->configdRun('layer7security ' . $action);
        $d = json_decode(trim((string)$out), true);
        return is_array($d) ? $d : [];
    }

    /** everything the license page shows */
    public function statusAction()
    {
        $st = License::status(true);
        $cloud = $this->json('license-cloud-status');
        $key = License::currentKey();
        return [
            'license' => $st,
            'key' => $key === '' ? '' : substr($key, 0, 11) . '-...-' . substr($key, -5),
            'server' => (string)$this->getModel()->general->feedUrl,
            'cloud' => $cloud,
            'now' => time(),
        ];
    }

    /** POST key */
    public function activateAction()
    {
        if (!$this->request->isPost()) {
            return ['ok' => false, 'message' => 'POST required'];
        }
        $key = License::normalize($this->request->getPost('key', 'string', ''));
        if (strlen($key) < 100) {
            return ['ok' => false, 'message' => 'Paste the whole license key.'];
        }
        $res = $this->json('license-activate', [implode('-', str_split($key, 5))]);
        return $res ?: ['ok' => false, 'message' => 'The key could not be activated.'];
    }

    /** POST: ask the cloud server for a 30 day trial key */
    public function trialAction()
    {
        if (!$this->request->isPost()) {
            return ['ok' => false, 'message' => 'POST required'];
        }
        return $this->json('license-trial') ?: ['ok' => false, 'message' => 'The cloud server did not answer.'];
    }

    /** POST server=http://host:8080/feeds (empty clears it) */
    public function serverAction()
    {
        if (!$this->request->isPost()) {
            return ['ok' => false, 'message' => 'POST required'];
        }
        $url = trim((string)$this->request->getPost('server', 'string', ''));
        if ($url !== '' && !preg_match('/^https?:\/\/[A-Za-z0-9.:\/_-]{1,200}$/', $url)) {
            return ['ok' => false, 'message' => 'Enter an address such as http://192.168.1.73:8080/feeds'];
        }
        Config::getInstance()->lock();
        $mdl = $this->getModel();
        $mdl->general->feedUrl = $url;
        $result = $this->validate();
        if (!empty($result['validations'])) {
            return ['ok' => false, 'message' => 'The address is not valid.'];
        }
        $this->save(false, true);
        return ['ok' => true];
    }

    /** POST: report to the cloud server and fetch the lists now */
    public function syncAction()
    {
        if (!$this->request->isPost()) {
            return ['ok' => false, 'message' => 'POST required'];
        }
        $checkin = $this->json('license-checkin');
        $feeds = [];
        if (!License::locked()) {
            $feeds = $this->json('feed-update-parts', ['domains,ips,hashes,signatures']);
        }
        return ['ok' => !empty($checkin['ok']), 'checkin' => $checkin, 'feeds' => $feeds, 'status' => $this->statusAction()];
    }

    /** POST: remove the key from this firewall */
    public function removeAction()
    {
        if (!$this->request->isPost()) {
            return ['ok' => false];
        }
        License::remove();
        (new Backend())->configdRun('layer7security license-check');
        return ['ok' => true];
    }
}
