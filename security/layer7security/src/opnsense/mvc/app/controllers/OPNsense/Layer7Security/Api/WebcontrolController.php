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

    /** clean up what was typed in the dialog before it is validated (URLs become host names) */
    private function normalizePost()
    {
        if (isset($_POST['rule']) && is_array($_POST['rule'])) {
            $kind = (string)($_POST['rule']['kind'] ?? 'domain');
            $value = (string)($_POST['rule']['value'] ?? '');
            $clean = $kind === 'ip' ? PolicyCompiler::normalizeIp($value) : PolicyCompiler::normalizeSite($value);
            if ($clean !== null) {
                $_POST['rule']['value'] = $clean;
            }
            unset($_POST['rule']['created'], $_POST['rule']['origin']);
        }
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
        $this->normalizePost();
        return $this->addBase('rule', 'webcontrol.rule', ['created' => (string)time(), 'origin' => 'manual']);
    }

    public function setRuleAction($uuid)
    {
        $this->normalizePost();
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
        if (strpos($rule, '/') === false) {
            return $rule === $ip;
        }
        [$net, $bits] = explode('/', $rule, 2);
        $a = @inet_pton($net);
        $b = @inet_pton($ip);
        if ($a === false || $b === false || strlen($a) !== strlen($b)) {
            return false;
        }
        $bits = (int)$bits;
        $full = intdiv($bits, 8);
        if ($full > 0 && substr($a, 0, $full) !== substr($b, 0, $full)) {
            return false;
        }
        $rem = $bits % 8;
        if ($rem === 0) {
            return true;
        }
        $mask = (0xff << (8 - $rem)) & 0xff;
        return (ord($a[$full]) & $mask) === (ord($b[$full]) & $mask);
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
