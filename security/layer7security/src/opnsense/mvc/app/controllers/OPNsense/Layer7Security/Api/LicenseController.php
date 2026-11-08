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
            'monitoring' => $this->json('agent-status'),
            'support' => (string)$this->getModel()->general->remoteSupport,
            'updates' => $this->json('update-status'),
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

    /** POST enabled=0|1: send (or stop sending) health and security status to the cloud server */
    public function monitoringAction()
    {
        if (!$this->request->isPost()) {
            return ['ok' => false, 'message' => 'POST required'];
        }
        $on = $this->request->getPost('enabled', 'string', '1') === '1';
        Config::getInstance()->lock();
        $mdl = $this->getModel();
        $mdl->general->monitoring = $on ? '1' : '0';
        $result = $this->validate();
        if (!empty($result['validations'])) {
            return ['ok' => false, 'message' => 'The setting is not valid.'];
        }
        $this->save(false, true);
        return ['ok' => true, 'enabled' => $on];
    }

    /** POST: look for a new plugin release now, and let OPNsense look for firmware and package updates */
    public function updatecheckAction()
    {
        if (!$this->request->isPost()) {
            return ['ok' => false, 'message' => 'POST required'];
        }
        $res = $this->json('update-check');
        (new Backend())->configdRun('layer7security update-firmware-check', true);
        return ['ok' => !empty($res['ok']), 'check' => $res, 'updates' => $this->json('update-status')];
    }

    /** POST: install the newest release (runs in the background, the page follows the state) */
    public function updateinstallAction()
    {
        if (!$this->request->isPost()) {
            return ['ok' => false, 'message' => 'POST required'];
        }
        return $this->json('update-install') ?: ['ok' => false, 'message' => 'The update could not be started.'];
    }

    /** POST: put the previous release back */
    public function updaterollbackAction()
    {
        if (!$this->request->isPost()) {
            return ['ok' => false, 'message' => 'POST required'];
        }
        return $this->json('update-rollback') ?: ['ok' => false, 'message' => 'The rollback could not be done.'];
    }

    /** POST channel=stable|beta auto=0|1 */
    public function updatesettingsAction()
    {
        if (!$this->request->isPost()) {
            return ['ok' => false, 'message' => 'POST required'];
        }
        $channel = (string)$this->request->getPost('channel', 'string', 'stable');
        $auto = (string)$this->request->getPost('auto', 'string', '0') === '1' ? '1' : '0';
        if (!in_array($channel, ['stable', 'beta'], true)) {
            return ['ok' => false, 'message' => 'Choose stable or beta.'];
        }
        Config::getInstance()->lock();
        $mdl = $this->getModel();
        $mdl->general->updateChannel = $channel;
        $mdl->general->autoUpdate = $auto;
        $result = $this->validate();
        if (!empty($result['validations'])) {
            return ['ok' => false, 'message' => 'The setting is not valid.'];
        }
        $this->save(false, true);
        return ['ok' => true];
    }

    /** POST level=off|view|manage: what the vendor may do remotely */
    public function supportAction()
    {
        if (!$this->request->isPost()) {
            return ['ok' => false, 'message' => 'POST required'];
        }
        $level = (string)$this->request->getPost('level', 'string', 'off');
        if (!in_array($level, ['off', 'view', 'manage'], true)) {
            return ['ok' => false, 'message' => 'Choose off, view or manage.'];
        }
        Config::getInstance()->lock();
        $mdl = $this->getModel();
        $mdl->general->remoteSupport = $level;
        $result = $this->validate();
        if (!empty($result['validations'])) {
            return ['ok' => false, 'message' => 'The setting is not valid.'];
        }
        $this->save(false, true);
        return ['ok' => true, 'level' => $level];
    }

    /** what the vendor looked at or changed, newest first */
    public function supportlogAction()
    {
        return $this->json('support-log', ['60']) + ['rows' => []];
    }

    /** POST: report to the cloud server and fetch the lists now */
    public function syncAction()
    {
        if (!$this->request->isPost()) {
            return ['ok' => false, 'message' => 'POST required'];
        }
        $checkin = $this->json('license-checkin');
        $this->json('agent-beat-now');
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
