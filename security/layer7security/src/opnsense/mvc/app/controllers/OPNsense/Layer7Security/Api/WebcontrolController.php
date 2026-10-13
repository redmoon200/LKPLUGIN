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
use OPNsense\Layer7Security\PolicyCompiler;

/**
 * Web Control: allow and block lists of websites (with wildcards) and IP
 * addresses. Also the target of the quick actions of the live session console.
 */
class WebcontrolController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'layer7security';
    protected static $internalModelClass = '\OPNsense\Layer7Security\Layer7Security';

    private const FIELDS = ['enabled', 'kind', 'value', 'action', 'sources', 'expires', 'origin', 'created', 'description'];

    /**
     * Clean up what was typed in the dialog before it is validated (a pasted URL becomes a host name).
     * Returns a validation error for names the engine would not use, or null when all is well.
     */
    private function normalizePost()
    {
        if (isset($_POST['rule']) && is_array($_POST['rule'])) {
            $kind = (string)($_POST['rule']['kind'] ?? 'domain');
            $value = (string)($_POST['rule']['value'] ?? '');
            $clean = $kind === 'ip' ? PolicyCompiler::normalizeIp($value) : PolicyCompiler::normalizeSite($value);
            unset($_POST['rule']['created'], $_POST['rule']['origin']);
            if ($clean === null) {
                return ['result' => 'failed', 'validations' => ['rule.value' => $kind === 'ip' ?
                    'Enter an IP address or network such as 203.0.113.7 or 203.0.113.0/24.' :
                    'Enter a website with a dot or a wildcard, such as example.com, *.example.com or *instagram.com.']];
            }
            if ($kind === 'ip' && (string)($_POST['rule']['action'] ?? 'block') === 'block' && PolicyCompiler::coversFirewall($clean)) {
                return ['result' => 'failed', 'validations' => ['rule.value' =>
                    'This address or network includes the firewall itself. Blocking it would cut off the management access.']];
            }
            $_POST['rule']['value'] = $clean;
        }
        return null;
    }

    public function searchRuleAction()
    {
        $kind = (string)$this->request->get('kind', 'string', '');
        $only = (string)$this->request->get('only', 'string', '');
        $now = time();
        return $this->searchBase('webcontrol.rule', self::FIELDS, 'created', function ($r) use ($kind, $only, $now) {
            if ($kind !== '' && (string)$r->kind !== $kind) {
                return false;
            }
            $exp = (int)(string)$r->expires;
            if ($only === 'temporary') {
                return $exp > 0;
            }
            return true;
        });
    }

    public function getRuleAction($uuid = null)
    {
        return $this->getBase('rule', 'webcontrol.rule', $uuid);
    }

    public function addRuleAction()
    {
        if (($err = $this->normalizePost()) !== null) {
            return $err;
        }
        return $this->addBase('rule', 'webcontrol.rule', ['created' => (string)time(), 'origin' => 'manual']);
    }

    public function setRuleAction($uuid)
    {
        if (($err = $this->normalizePost()) !== null) {
            return $err;
        }
        return $this->setBase('rule', 'webcontrol.rule', $uuid);
    }

    /** turn a temporary rule into a permanent one */
    public function permanentAction($uuid)
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        Config::getInstance()->lock();
        $node = $this->getModel()->getNodeByReference('webcontrol.rule.' . $uuid);
        if ($node === null) {
            return ['result' => 'failed'];
        }
        $node->expires = '0';
        $this->save(false, true);
        return ['result' => 'saved'];
    }

    public function delRuleAction($uuid)
    {
        return $this->delBase('webcontrol.rule', $uuid);
    }

    public function toggleRuleAction($uuid, $enabled = null)
    {
        return $this->toggleBase('webcontrol.rule', $uuid, $enabled);
    }

    /**
     * One call for the quick actions: add (or flip) a rule and apply it.
     * POST kind=domain|ip value=... action=block|allow minutes=0..N source=ip|"" note=...
     */
    public function quickAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }
        $kind = $this->request->getPost('kind', 'string', 'domain') === 'ip' ? 'ip' : 'domain';
        $action = $this->request->getPost('action', 'string', 'block') === 'allow' ? 'allow' : 'block';
        $value = $kind === 'ip' ?
            PolicyCompiler::normalizeIp((string)$this->request->getPost('value', 'string', '')) :
            PolicyCompiler::normalizeSite((string)$this->request->getPost('value', 'string', ''));
        if ($value === null) {
            return ['result' => 'failed', 'message' => 'That is not a valid ' . ($kind === 'ip' ? 'IP address' : 'website') . '.'];
        }
        if ($kind === 'ip' && $action === 'block' && PolicyCompiler::coversFirewall($value)) {
            return ['result' => 'failed', 'message' => 'That address belongs to the firewall itself. Blocking it would cut off the management access.'];
        }
        $minutes = max(0, min(525600, (int)$this->request->getPost('minutes', 'int', 0)));
        $source = trim((string)$this->request->getPost('source', 'string', ''));
        if ($source !== '' && PolicyCompiler::normalizeIp($source) === null) {
            return ['result' => 'failed', 'message' => 'The device address is not valid.'];
        }
        $note = preg_replace('/[^\x20-\x7e]/', '', (string)$this->request->getPost('note', 'string', ''));
        $note = substr($note, 0, 120);
        $apply = $this->request->getPost('apply', 'string', '1') !== '0';

        Config::getInstance()->lock();
        $mdl = $this->getModel();
        $now = time();
        $changed = 'added';
        /* the opposite rule for the same target and scope is replaced; the same rule only gets a new end time */
        foreach ($mdl->webcontrol->rule->iterateItems() as $uuid => $r) {
            if ((string)$r->kind !== $kind || strtolower((string)$r->value) !== $value) {
                continue;
            }
            if (implode(',', array_filter(explode(',', (string)$r->sources))) !== $source) {
                continue;
            }
            if ((string)$r->action === $action) {
                $r->enabled = '1';
                $r->expires = (string)($minutes > 0 ? $now + $minutes * 60 : 0);
                $changed = 'updated';
                $node = $r;
            } else {
                $mdl->webcontrol->rule->del($uuid);
                $changed = 'replaced';
            }
        }
        if (!isset($node)) {
            $node = $mdl->webcontrol->rule->Add();
            $node->setNodes([
                'enabled' => '1', 'kind' => $kind, 'value' => $value, 'action' => $action, 'sources' => $source,
                'expires' => (string)($minutes > 0 ? $now + $minutes * 60 : 0), 'origin' => 'live',
                'created' => (string)$now, 'description' => $note,
            ]);
        }
        $result = $this->validate($node, 'rule');
        if (!empty($result['validations'])) {
            return ['result' => 'failed', 'message' => implode(' ', array_values($result['validations']))];
        }
        $this->save(false, true);
        $out = ['result' => 'saved', 'change' => $changed, 'value' => $value, 'action' => $action,
                'uuid' => $node->getAttribute('uuid')];
        if ($apply) {
            $res = trim((new Backend())->configdRun('layer7security apply'));
            $out['applied'] = $res === 'OK';
            if ($res !== 'OK') {
                $out['message'] = $res;
            }
        }
        return $out;
    }

    /**
     * Add many websites or IP addresses at once: POST text="one per line (or comma separated)"
     * action=block|allow. Entries that already exist with the same action are skipped.
     */
    public function bulkAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $action = $this->request->getPost('action', 'string', 'block') === 'allow' ? 'allow' : 'block';
        $source = trim((string)$this->request->getPost('source', 'string', ''));
        if ($source !== '' && PolicyCompiler::normalizeIp($source) === null) {
            return ['result' => 'failed', 'message' => 'The device address is not valid.'];
        }
        $items = preg_split('/[\s,;]+/', (string)$this->request->getPost('text', null, ''), -1, PREG_SPLIT_NO_EMPTY);
        $items = array_slice($items ?: [], 0, 1000);
        Config::getInstance()->lock();
        $mdl = $this->getModel();
        $have = [];
        foreach ($mdl->webcontrol->rule->iterateItems() as $r) {
            $have[(string)$r->kind . '|' . strtolower((string)$r->value) . '|' . (string)$r->action . '|' . (string)$r->sources] = true;
        }
        $added = 0;
        $skipped = 0;
        $invalid = [];
        $now = time();
        foreach ($items as $item) {
            $ip = PolicyCompiler::normalizeIp($item);
            $kind = $ip !== null ? 'ip' : 'domain';
            $value = $ip ?? PolicyCompiler::normalizeSite($item);
            if ($value === null) {
                $invalid[] = substr($item, 0, 60);
                continue;
            }
            if ($kind === 'ip' && $action === 'block' && PolicyCompiler::coversFirewall($value)) {
                $invalid[] = $item . ' (the firewall itself)';
                continue;
            }
            $key = $kind . '|' . $value . '|' . $action . '|' . $source;
            if (isset($have[$key])) {
                $skipped++;
                continue;
            }
            $have[$key] = true;
            $node = $mdl->webcontrol->rule->Add();
            $node->setNodes(['enabled' => '1', 'kind' => $kind, 'value' => $value, 'action' => $action, 'sources' => $source,
                'expires' => '0', 'origin' => 'import', 'created' => (string)$now, 'description' => 'imported']);
            $added++;
        }
        $result = $this->validate();
        if (!empty($result['validations'])) {
            return ['result' => 'failed', 'message' => implode(' ', array_slice(array_values($result['validations']), 0, 3))];
        }
        if ($added > 0) {
            $this->save(false, true);
        }
        return ['result' => 'saved', 'added' => $added, 'skipped' => $skipped, 'invalid' => array_slice($invalid, 0, 20)];
    }

    /** which rules would match this website or address, and what happens to it */
    public function testAction()
    {
        $q = $this->request->getPost('q', 'string', $this->request->get('q', 'string', ''));
        $site = PolicyCompiler::normalizeSite((string)$q);
        $ip = PolicyCompiler::normalizeIp((string)$q);
        $matches = [];
        $verdict = 'none';
        foreach (PolicyCompiler::webRules() as $r) {
            $hit = false;
            if ($r['kind'] === 'domain' && $site !== null && strpbrk($site, '*?') === false) {
                $hit = self::hostMatch($r['value'], $site);
            } elseif ($r['kind'] === 'ip' && $ip !== null && strpos($ip, '/') === false) {
                $hit = self::ipMatch($r['value'], $ip);
            }
            if ($hit) {
                $matches[] = ['value' => $r['value'], 'action' => $r['action'], 'sources' => $r['sources']];
            }
        }
        foreach ($matches as $m) {
            if ($m['action'] === 'allow') {
                $verdict = 'allow';
                break;
            }
            $verdict = 'block';
        }
        return ['query' => (string)($site ?? $ip ?? ''), 'verdict' => $verdict, 'matches' => $matches];
    }

    /** same rules as the engine: plain name = the name and everything below it, * and ? make it a glob */
    public static function hostMatch($pattern, $host)
    {
        if (strpbrk($pattern, '*?') !== false) {
            if (strncmp($pattern, '*.', 2) === 0 && strpbrk(substr($pattern, 2), '*?') === false && self::hostMatch(substr($pattern, 2), $host)) {
                return true;
            }
            return fnmatch($pattern, $host, FNM_CASEFOLD);
        }
        return $host === $pattern || substr($host, -strlen($pattern) - 1) === '.' . $pattern;
    }

    private static function ipMatch($rule, $ip)
    {
        return PolicyCompiler::ipInNet($rule, $ip);
    }

    /** numbers for the module header */
    public function statusAction()
    {
        $rules = PolicyCompiler::webRules();
        $count = ['domain' => 0, 'ip' => 0, 'block' => 0, 'allow' => 0, 'temporary' => 0];
        foreach ($rules as $r) {
            $count[$r['kind']]++;
            $count[$r['action']]++;
            if ($r['expires'] > 0) {
                $count['temporary']++;
            }
        }
        $general = PolicyCompiler::general();
        return ['enabled' => $general['enabled'] && $general['webEnabled'], 'rules' => $count, 'total' => count($rules)];
    }
}
