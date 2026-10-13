<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Layer7Security\Layer7Security;

/**
 * AI audit log. Every read, export and verification is itself recorded in the
 * hash chain, and the controller has its own ACL entry so access can be
 * limited to auditors.
 */
class AuditController extends ApiControllerBase
{
    private const PERIODS = [300, 3600, 21600, 86400, 604800, 2592000, 31536000];

    private function user()
    {
        return preg_replace('/[^A-Za-z0-9_.@-]/', '', (string)$this->getUserName()) ?: 'unknown';
    }

    private function period($value, $default = 86400)
    {
        $p = (int)$value;
        return in_array($p, self::PERIODS, true) ? $p : $default;
    }

    private function record($what)
    {
        (new Backend())->configdpRun('layer7security audit-access', [$this->user(), $what]);
    }

    /** bootgrid compatible listing */
    public function searchAction()
    {
        $current = max(1, (int)$this->request->getPost('current', 'int', 1));
        $rows = (int)$this->request->getPost('rowCount', 'int', 25);
        $rows = ($rows < 1 || $rows > 500) ? 25 : $rows;
        $phrase = substr(trim(preg_replace('/[^A-Za-z0-9._:\/@ -]/', '', (string)$this->request->getPost('searchPhrase', 'string', ''))), 0, 64);
        $kind = preg_replace('/[^a-z-]/', '', (string)$this->request->getPost('kind', 'string', ''));
        $this->record('view');
        $out = (new Backend())->configdpRun('layer7security audit-list', [
            $rows, ($current - 1) * $rows, $this->period($this->request->getPost('period', 'int', 86400)),
            $kind === '' ? '-' : $kind, $phrase === '' ? '-' : $phrase
        ]);
        $data = json_decode(trim($out), true);
        if (!is_array($data) || !isset($data['rows'])) {
            return ['rows' => [], 'rowCount' => 0, 'total' => 0, 'current' => $current];
        }
        $data['rowCount'] = count($data['rows']);
        $data['current'] = $current;
        return $data;
    }

    public function verifyAction()
    {
        $this->record('verify');
        $data = json_decode(trim((new Backend())->configdpRun('layer7security audit-verify', [$this->user()])), true);
        return is_array($data) ? $data : ['ok' => false, 'reason' => 'verification failed to run'];
    }

    public function statusAction()
    {
        $data = json_decode(trim((new Backend())->configdRun('layer7security audit-status')), true);
        return is_array($data) ? $data : [];
    }

    /** download: csv, json (with manifest) or jsonl */
    public function exportAction()
    {
        $fmt = (string)$this->request->get('format', 'string', 'json');
        $fmt = in_array($fmt, ['csv', 'json', 'jsonl'], true) ? $fmt : 'json';
        $per = $this->period($this->request->get('period', 'int', 86400));
        $this->record('export');
        $content = (new Backend())->configdpRun('layer7security audit-export', [$fmt, $per, $this->user()]);
        $types = ['csv' => 'text/csv', 'json' => 'application/json', 'jsonl' => 'application/x-ndjson'];
        $this->response->setContentType($types[$fmt], 'UTF-8');
        $this->response->setHeader('Content-Disposition', 'attachment; filename="ai-audit-' . date('Ymd-His') . '.' . $fmt . '"');
        $this->response->setHeader('X-Content-Type-Options', 'nosniff');
        $this->response->setContent($content);
        return;
    }

    /**
     * Audit settings can only be changed through this privileged endpoint, so
     * administrators without the audit privilege cannot switch the log off.
     */
    public function setAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $post = $this->request->getPost('layer7security');
        $in = is_array($post) && isset($post['audit']) && is_array($post['audit']) ? $post['audit'] : [];
        $allowed = ['enabled', 'retentionDays', 'syslogLocal', 'syslogTarget', 'noticeText'];
        $audit = array_intersect_key($in, array_flip($allowed));
        Config::getInstance()->lock();
        $mdl = new Layer7Security();
        $mdl->setNodes(['audit' => $audit]);
        $result = ['result' => 'failed', 'validations' => []];
        foreach ($mdl->performValidation() as $msg) {
            $result['validations']['layer7security.' . $msg->getField()] = $msg->getMessage();
        }
        if (!empty($result['validations'])) {
            Config::getInstance()->unlock();
            return $result;
        }
        $mdl->serializeToConfig();
        Config::getInstance()->save();
        $this->record('config');
        return ['result' => 'saved'];
    }

    /** the privacy notice text shown before anything is logged */
    public function noticeAction()
    {
        $default = trim((string)@file_get_contents('/usr/local/share/layer7security/privacy_notice.txt'));
        $mdl = new Layer7Security();
        return [
            'notice' => $default,
            'custom' => (string)$mdl->audit->noticeText,
            'ackBy' => (string)$mdl->audit->privacyAckBy,
            'ackAt' => (string)$mdl->audit->privacyAckAt,
        ];
    }

    /** the administrator confirms that users have been informed */
    public function ackAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        Config::getInstance()->lock();
        $mdl = new Layer7Security();
        $mdl->audit->privacyAckBy = $this->user();
        $mdl->audit->privacyAckAt = date('c');
        $mdl->serializeToConfig();
        Config::getInstance()->save();
        $this->record('ack');
        return ['result' => 'saved', 'ackBy' => $this->user(), 'ackAt' => (string)$mdl->audit->privacyAckAt];
    }
}
