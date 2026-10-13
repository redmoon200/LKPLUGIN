<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security;

use OPNsense\Core\Config;

/**
 * Turns the model (policies, users, interfaces) into plain arrays that the
 * engine config, the pf hook and the DNS filter generator all share, so ids
 * and table names stay consistent between them.
 */
class PolicyCompiler
{
    private const DAYS = ['sun' => 0, 'mon' => 1, 'tue' => 2, 'wed' => 3, 'thu' => 4, 'fri' => 5, 'sat' => 6];

    private static function csv($value)
    {
        return array_values(array_filter(array_map('trim', explode(',', (string)$value)), 'strlen'));
    }

    /** device name (e.g. vtnet0, vlan0.10) of an interface identifier */
    public static function device($ifid)
    {
        $cfg = Config::getInstance()->object();
        if (isset($cfg->interfaces->$ifid) && !empty((string)$cfg->interfaces->$ifid->if)) {
            return (string)$cfg->interfaces->$ifid->if;
        }
        return null;
    }

    /** IPv4 network (CIDR) of an interface with a static address, else null */
    public static function network($ifid)
    {
        $cfg = Config::getInstance()->object();
        if (!isset($cfg->interfaces->$ifid)) {
            return null;
        }
        $ip = (string)$cfg->interfaces->$ifid->ipaddr;
        $bits = (int)$cfg->interfaces->$ifid->subnet;
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false || $bits < 1 || $bits > 32) {
            return null;
        }
        $mask = $bits == 32 ? 0xffffffff : ((0xffffffff << (32 - $bits)) & 0xffffffff);
        return long2ip(ip2long($ip) & $mask) . '/' . $bits;
    }

    public static function general()
    {
        $mdl = new Layer7Security();
        $g = $mdl->general;
        $ifs = self::csv($g->interfaces);
        if (empty($ifs)) {
            $ifs = ['lan'];
        }
        $devices = [];
        foreach ($ifs as $ifid) {
            $dev = self::device($ifid);
            if ($dev !== null) {
                $devices[] = $dev;
            }
        }
        return self::withDerived([
            'enabled' => (string)$g->enabled === '1',
            'enforce' => (string)$g->enforce === '1',
            'devices' => $devices,
            'ifids' => $ifs,
            'retention' => (int)(string)$g->retention,
            'flowTimeout' => (int)(string)$g->flowTimeout,
            'blockTtl' => (int)(string)$g->blockTtl,
            'dnsFilter' => (string)$g->dnsFilter === '1',
            'dnsMode' => (string)$g->dnsMode ?: 'nxdomain',
            'dnsCategories' => self::csv($g->dnsCategories),
            'dnsBlock' => array_map('strtolower', self::csv($g->dnsBlock)),
            'dnsAllow' => array_map('strtolower', self::csv($g->dnsAllow)),
            'feedUrl' => (string)$g->feedUrl,
            'macMode' => (string)$g->macMode ?: 'off',
            'macInterfaces' => self::csv($g->macInterfaces) ?: ['lan'],
            'macStaticArp' => (string)$g->macStaticArp === '1',
            'geoEnabled' => (string)$g->geoEnabled === '1',
            'geoSource' => (string)$g->geoSource,
            'aiEnabled' => (string)$g->aiEnabled === '1',
            'aiDefault' => (string)$g->aiDefault ?: 'monitor',
            'aiQuic' => (string)$g->aiQuic ?: 'off',
            'auditEnabled' => (string)$mdl->audit->enabled === '1',
            'privacyAck' => (string)$mdl->audit->privacyAckBy !== '' && (string)$mdl->audit->privacyAckAt !== '',
            'dlpEnabled' => (string)$mdl->dlp->enabled === '1',
            'dlpInspectDefault' => (string)$mdl->dlp->inspectDefault === '1',
            'avEnabled' => (string)$mdl->av->enabled === '1',
            'avHttp' => (string)$mdl->av->scanHttp === '1',
            'avHttpsDomains' => array_map('strtolower', self::csv($mdl->av->httpsDomains)),
            'webEnabled' => (string)$mdl->webcontrol->enabled === '1',
            'safeSearch' => (string)$mdl->cfs->safeSearch === '1',
            'youtubeMode' => (string)$mdl->cfs->youtube ?: 'off',
            'threatIps' => self::csv($mdl->cfs->threatIps),
            'threatDirection' => (string)$mdl->cfs->threatDirection ?: 'both',
        ], $mdl);
    }

    /** values that depend on several settings */
    private static function withDerived(array $g, $mdl)
    {
        /* content inspection and web antivirus on HTTPS need the privacy notice acknowledged */
        $g['inspectionAllowed'] = $g['dlpEnabled'] && $g['privacyAck'];
        $inspect = $g['inspectionAllowed'] && $g['dlpInspectDefault'];
        foreach ($mdl->ai->service->iterateItems() as $row) {
            if ((string)$row->enabled === '1' && (string)$row->inspect === '1' && (string)$row->action !== 'block') {
                $inspect = $inspect || $g['inspectionAllowed'];
            }
        }
        $g['avHttpsAllowed'] = $g['avEnabled'] && $g['privacyAck'] && !empty($g['avHttpsDomains']);
        /* the engine fills the proxy redirect table for AI inspection and for AV-selected HTTPS domains */
        $g['aiInspect'] = $g['aiEnabled'] && $inspect || $g['avHttpsAllowed'];
        $g['proxyNeeded'] = ($g['aiEnabled'] && $inspect) || $g['avHttpsAllowed'] || ($g['avEnabled'] && $g['avHttp']);
        return $g;
    }

    /** AI service catalog (id => [name, domains, ...]) */
    public static function aiCatalog()
    {
        $data = json_decode(@file_get_contents('/usr/local/share/layer7security/ai_services.json') ?: '[]', true);
        $out = [];
        foreach (is_array($data) ? $data : [] as $svc) {
            if (!empty($svc['id']) && !empty($svc['domains'])) {
                $out[$svc['id']] = $svc;
            }
        }
        return $out;
    }

    /** source networks of a model row: explicit sources plus the addresses of the selected users */
    private static function rowSources($mdl, $row)
    {
        $sources = self::csv($row->sources);
        foreach (self::csv($row->users) as $uid) {
            $user = $mdl->getNodeByReference('users.user.' . $uid);
            if ($user !== null) {
                foreach (self::csv($user->addresses) as $addr) {
                    $sources[] = $addr;
                }
            }
        }
        return array_values(array_unique($sources));
    }

    private static function dayMask($row)
    {
        $mask = 0;
        foreach (self::csv($row->days) as $day) {
            if (isset(self::DAYS[$day])) {
                $mask |= 1 << self::DAYS[$day];
            }
        }
        return $mask ?: 0x7f;
    }

    /**
     * Engine policies for AI services. Rules configured per service come first,
     * then one catch-all per service with the default action, so the first
     * match decides. Hosts are suffix-matched against the TLS/QUIC server name
     * and DNS answers.
     */
    public static function aiPolicies(array $general)
    {
        if (!$general['aiEnabled'] && !$general['avHttpsAllowed']) {
            return [];
        }
        $catalog = $general['aiEnabled'] ? self::aiCatalog() : [];
        $mdl = new Layer7Security();
        $quic = $general['aiQuic'] === 'ai';
        $out = [];
        foreach ($general['aiEnabled'] ? $mdl->ai->service->iterateItems() : [] as $uuid => $row) {
            $id = (string)$row->service;
            if ((string)$row->enabled !== '1' || !isset($catalog[$id])) {
                continue;
            }
            $out[] = [
                'uuid' => $uuid, 'name' => 'AI: ' . $catalog[$id]['name'], 'action' => (string)$row->action,
                'ifids' => [], 'devices' => [], 'sources' => self::rowSources($mdl, $row),
                'apps' => [], 'cats' => [], 'hosts' => array_map('strtolower', $catalog[$id]['domains']),
                'dayMask' => self::dayMask($row), 'start' => (string)$row->startTime, 'end' => (string)$row->endTime,
                'dnsCategories' => [], 'dnsDomains' => [], 'ai' => $id,
                'inspect' => (string)$row->inspect === '1' && $general['inspectionAllowed'], 'quic' => $quic,
            ];
        }
        foreach ($catalog as $id => $svc) {
            $out[] = [
                'uuid' => 'ai-default-' . $id, 'name' => 'AI: ' . $svc['name'] . ' (default)',
                'action' => $general['aiDefault'], 'ifids' => [], 'devices' => [], 'sources' => [],
                'apps' => [], 'cats' => [], 'hosts' => array_map('strtolower', $svc['domains']),
                'dayMask' => 0x7f, 'start' => '00:00', 'end' => '00:00',
                'dnsCategories' => [], 'dnsDomains' => [], 'ai' => $id,
                'inspect' => $general['dlpInspectDefault'] && $general['inspectionAllowed'], 'quic' => $quic,
            ];
        }
        /* HTTPS download domains the antivirus should see: steered to the proxy like inspected AI services */
        if ($general['avHttpsAllowed']) {
            foreach ($general['avHttpsDomains'] as $dom) {
                $out[] = [
                    'uuid' => 'av-' . $dom, 'name' => 'AV: ' . $dom, 'action' => 'monitor', 'ifids' => [],
                    'devices' => [], 'sources' => [], 'apps' => [], 'cats' => [], 'hosts' => [$dom], 'dayMask' => 0x7f,
                    'start' => '00:00', 'end' => '00:00', 'dnsCategories' => [], 'dnsDomains' => [], 'ai' => '',
                    'inspect' => true, 'quic' => false,
                ];
            }
        }
        return $out;
    }

    /**
     * Enabled policies in evaluation order. Ids are positions (1..n) so the
     * pf table name l7_blk_<id> matches in the engine and in the pf hook.
     */
    public static function policies()
    {
        $mdl = new Layer7Security();
        $rows = [];
        foreach ($mdl->policies->policy->iterateItems() as $uuid => $p) {
            if ((string)$p->enabled !== '1') {
                continue;
            }
            $rows[] = ['seq' => (int)(string)$p->sequence, 'name' => (string)$p->name, 'uuid' => $uuid, 'node' => $p];
        }
        usort($rows, function ($a, $b) {
            return [$a['seq'], $a['name'], $a['uuid']] <=> [$b['seq'], $b['name'], $b['uuid']];
        });

        $result = [];
        $id = 0;
        foreach (self::webPolicies(self::general()) as $web) {
            $id++;
            $result[] = array_merge($web, ['id' => $id, 'table' => 'l7_blk_' . $id]);
        }
        foreach (self::aiPolicies(self::general()) as $ai) {
            $id++;
            $result[] = array_merge($ai, ['id' => $id, 'table' => 'l7_blk_' . $id]);
        }
        foreach ($rows as $row) {
            $p = $row['node'];
            $id++;
            $ifids = self::csv($p->interfaces);
            $sources = self::csv($p->sources);
            foreach ($ifids as $ifid) {
                $net = self::network($ifid);
                if ($net !== null) {
                    $sources[] = $net;
                }
            }
            $unames = [];
            foreach (self::csv($p->users) as $uid) {
                $user = $mdl->getNodeByReference('users.user.' . $uid);
                if ($user !== null) {
                    $unames[] = self::userKey((string)$user->name);
                    foreach (self::csv($user->addresses) as $addr) {
                        $sources[] = $addr;
                    }
                }
            }
            $mask = 0;
            foreach (self::csv($p->days) as $day) {
                if (isset(self::DAYS[$day])) {
                    $mask |= 1 << self::DAYS[$day];
                }
            }
            $devices = [];
            foreach ($ifids as $ifid) {
                $dev = self::device($ifid);
                if ($dev !== null) {
                    $devices[$ifid] = $dev;
                }
            }
            $result[] = [
                'id' => $id,
                'uuid' => $row['uuid'],
                'name' => $row['name'],
                'action' => (string)$p->action,
                'ifids' => $ifids,
                'devices' => $devices,
                'sources' => array_values(array_unique($sources)),
                'apps' => self::csv($p->applications),
                'cats' => self::csv($p->categories),
                'hosts' => array_map('strtolower', self::csv($p->hosts)),
                'dayMask' => $mask ?: 0x7f,
                'start' => (string)$p->startTime,
                'end' => (string)$p->endTime,
                'dnsCategories' => self::csv($p->dnsCategories),
                'dnsDomains' => array_map('strtolower', self::csv($p->dnsDomains)),
                'table' => 'l7_blk_' . $id,
                'ai' => '', 'inspect' => false, 'quic' => false,
                'module' => (string)$p->module ?: 'app',
                'users' => array_values(array_unique($unames)),
                'restrict' => !empty($sources) || !empty($unames),
            ];
        }
        return $result;
    }

    /** a user name as used in the session map and the engine (no separators) */
    public static function userKey($name)
    {
        return preg_replace('/[\s,|:;\x00-\x1f]/', '_', trim((string)$name));
    }

    /** lower-case host name from what an administrator typed ("https://www.Example.com/path" -> www.example.com) */
    public static function normalizeSite($value)
    {
        $v = strtolower(trim((string)$value));
        $v = preg_replace('#^[a-z][a-z0-9+.-]*://#', '', $v);
        $v = preg_replace('#[/?\#].*$#', '', $v);
        $v = preg_replace('#^[^@]*@#', '', $v);
        $v = preg_replace('#:[0-9]+$#', '', $v);
        $v = rtrim($v, '.');
        if (
            $v === '' || strlen($v) > 90 || strpos($v, '..') !== false ||
            !preg_match('/^(\*\.?)?[a-z0-9?*]([a-z0-9._?*-]*[a-z0-9?*])?$/', $v)
        ) {
            return null;
        }
        return $v;
    }

    /** the DNS zone that blocks the same names as a pattern, null when DNS cannot express it */
    public static function dnsZone($pattern)
    {
        $z = preg_replace('/^\*\.?/', '', $pattern);
        if ($z === '' || strpbrk($z, '*?') !== false || strpos($z, '.') === false) {
            return null;
        }
        return $z;
    }

    /**
     * Web Control rules that are active now: enabled, not expired, normalised.
     */
    public static function webRules($now = null)
    {
        $now = $now ?? time();
        $mdl = new Layer7Security();
        $out = [];
        foreach ($mdl->webcontrol->rule->iterateItems() as $uuid => $r) {
            if ((string)$r->enabled !== '1') {
                continue;
            }
            $exp = (int)(string)$r->expires;
            if ($exp > 0 && $exp <= $now) {
                continue;
            }
            $kind = (string)$r->kind;
            $value = $kind === 'domain' ? self::normalizeSite((string)$r->value) : self::normalizeIp((string)$r->value);
            if ($value === null) {
                continue;
            }
            $out[] = [
                'uuid' => $uuid, 'kind' => $kind, 'value' => $value, 'action' => (string)$r->action,
                'sources' => self::csv($r->sources), 'expires' => $exp, 'origin' => (string)$r->origin,
                'created' => (int)(string)$r->created,
            ];
        }
        usort($out, function ($a, $b) {
            return [$a['created'], $a['value']] <=> [$b['created'], $b['value']];
        });
        return $out;
    }

    /** IPv4/IPv6 address or network in canonical text form, null when invalid */
    public static function normalizeIp($value)
    {
        $v = strtolower(trim((string)$value));
        $bits = null;
        if (strpos($v, '/') !== false) {
            [$v, $bits] = explode('/', $v, 2);
            if (!ctype_digit($bits)) {
                return null;
            }
            $bits = (int)$bits;
        }
        $v4 = filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        $v6 = !$v4 && filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        if (!$v4 && !$v6) {
            return null;
        }
        if ($bits !== null && ($bits < 0 || $bits > ($v4 ? 32 : 128))) {
            return null;
        }
        return $bits === null ? $v : $v . '/' . $bits;
    }

    /** host patterns per engine policy (the engine keeps 128 per policy) */
    private const WEB_CHUNK = 100;

    /**
     * Engine policies for Web Control domain rules: allow rules first (an allow
     * wins over every block), then block rules grouped by who they apply to.
     */
    public static function webPolicies(array $general)
    {
        if (!$general['webEnabled']) {
            return [];
        }
        $groups = ['allow' => [], 'block' => []];
        foreach (self::webRules() as $r) {
            if ($r['kind'] !== 'domain') {
                continue;
            }
            $key = implode(',', $r['sources']);
            $groups[$r['action']][$key]['sources'] = $r['sources'];
            $groups[$r['action']][$key]['hosts'][$r['value']] = true;
        }
        $out = [];
        foreach ($groups as $action => $byScope) {
            ksort($byScope);
            foreach ($byScope as $scope => $g) {
                $hosts = array_keys($g['hosts']);
                foreach (array_chunk($hosts, self::WEB_CHUNK) as $n => $chunk) {
                    $zones = [];
                    foreach ($chunk as $h) {
                        $z = self::dnsZone($h);
                        if ($z !== null) {
                            $zones[] = $z;
                        }
                    }
                    $out[] = [
                        'uuid' => 'web-' . $action . '-' . md5($scope) . '-' . $n,
                        'name' => 'Web Control: ' . $action . ($scope === '' ? '' : ' for ' . substr($scope, 0, 40)) .
                            (count($hosts) > self::WEB_CHUNK ? ' (' . ($n + 1) . ')' : ''),
                        'action' => $action, 'ifids' => [], 'devices' => [], 'sources' => $g['sources'],
                        'apps' => [], 'cats' => [], 'hosts' => $chunk, 'dayMask' => 0x7f, 'start' => '00:00',
                        'end' => '00:00', 'dnsCategories' => [], 'dnsDomains' => $zones, 'ai' => '',
                        'inspect' => false, 'quic' => false, 'module' => 'web', 'users' => [],
                        'restrict' => !empty($g['sources']),
                    ];
                }
            }
        }
        return $out;
    }

    /**
     * IP rules of Web Control as pf table groups: one table per set of client
     * sources. Allow rules apply to everyone and are entered into every table
     * as negated (!) entries, which pf resolves by the most specific match.
     */
    public static function webIpGroups(array $general)
    {
        if (!$general['webEnabled']) {
            return [];
        }
        $allow = [];
        $groups = [];
        foreach (self::webRules() as $r) {
            if ($r['kind'] !== 'ip') {
                continue;
            }
            if ($r['action'] === 'allow') {
                $allow[$r['value']] = true;
                continue;
            }
            $key = implode(',', $r['sources']);
            $groups[$key]['sources'] = $r['sources'];
            $groups[$key]['blocked'][$r['value']] = true;
        }
        ksort($groups);
        $out = [];
        $n = 0;
        foreach ($groups as $g) {
            $n++;
            $blocked = array_keys($g['blocked']);
            $entries = $blocked;
            foreach (array_keys($allow) as $a) {
                $entries[] = '!' . $a;
            }
            $out[] = [
                'id' => $n, 'table' => 'l7_ipb_' . $n, 'sources' => $g['sources'], 'entries' => $entries,
                'blocked' => $blocked, 'file' => '/var/db/layer7security/webip_' . $n . '.txt',
            ];
        }
        return $out;
    }

    /** threat IP lists the cloud server offers */
    public const THREAT_IP_LISTS = ['c2', 'compromised', 'attackers', 'drop', 'tor'];

    /** enabled threat IP lists with their pf table and file */
    public static function threatLists(array $general)
    {
        $out = [];
        foreach ($general['threatIps'] as $id) {
            if (in_array($id, self::THREAT_IP_LISTS, true)) {
                $out[] = ['id' => $id, 'table' => 'l7_thr_' . $id, 'file' => '/var/db/layer7security/threat/' . $id . '.txt'];
            }
        }
        return $out;
    }

    /** normalise a MAC address to lower-case aa:bb:cc:dd:ee:ff, null when invalid */
    public static function normalizeMac($mac)
    {
        $mac = strtolower(trim((string)$mac));
        return preg_match('/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/', $mac) ? $mac : null;
    }

    /**
     * Enabled MAC bindings with the device name of their interface.
     * An empty ip means "this MAC only"; an empty interface means every
     * interface selected for MAC enforcement.
     */
    public static function bindings()
    {
        $mdl = new Layer7Security();
        $result = [];
        foreach ($mdl->bindings->binding->iterateItems() as $uuid => $b) {
            if ((string)$b->enabled !== '1') {
                continue;
            }
            $mac = self::normalizeMac((string)$b->mac);
            if ($mac === null) {
                continue;
            }
            $ifid = (string)$b->interface;
            $result[] = [
                'uuid' => $uuid,
                'name' => (string)$b->name,
                'mac' => $mac,
                'ip' => (string)$b->ip,
                'ifid' => $ifid,
                'device' => $ifid !== '' ? self::device($ifid) : null,
            ];
        }
        return $result;
    }

    /**
     * pf ether rules for the MAC binding anchor. pf evaluates ether rules with
     * "last match wins", so the order below matters:
     *   1. strict: block all IPv4 from the interface, let DHCP discovery through
     *   2. MAC-only bindings may pass
     *   3. every IP that is bound is blocked for everybody ...
     *   4. ... and passed again for its own MAC only
     * IPv4 only (EtherType 0x0800); ARP and IPv6 are not touched.
     */
    public static function macRules(array $general, array $bindings)
    {
        if ($general['macMode'] === 'off' || !$general['enabled']) {
            return '';
        }
        $devices = [];
        foreach ($general['macInterfaces'] as $ifid) {
            $dev = self::device($ifid);
            if ($dev !== null) {
                $devices[$ifid] = $dev;
            }
        }
        $out = "# generated by os-layer7security, do not edit
";
        foreach ($devices as $ifid => $dev) {
            $mine = array_filter($bindings, function ($b) use ($ifid) {
                return $b['ifid'] === '' || $b['ifid'] === $ifid;
            });
            if ($general['macMode'] === 'strict') {
                if (empty($mine)) {
                    continue; /* never lock an interface out when nothing is bound */
                }
                $out .= "ether block in on $dev proto 0x800
";
                $out .= "ether pass in on $dev proto 0x800 l3 from 0.0.0.0
";
                foreach ($mine as $b) {
                    if ($b['ip'] === '') {
                        $out .= "ether pass in on $dev proto 0x800 from {$b['mac']}
";
                    }
                }
            }
            foreach ($mine as $b) {
                if ($b['ip'] === '') {
                    continue;
                }
                $out .= "ether block in on $dev proto 0x800 l3 from {$b['ip']}
";
                $out .= "ether pass in on $dev proto 0x800 from {$b['mac']} l3 from {$b['ip']}
";
            }
        }
        return $out;
    }

    /**
     * Enabled geo policies. Ids are positions (1..n); the pf table is
     * l7_geo_<id> and its CIDR file is written by geo_build.py.
     */
    public static function geoPolicies()
    {
        $mdl = new Layer7Security();
        $result = [];
        $id = 0;
        foreach ($mdl->geo->policy->iterateItems() as $uuid => $p) {
            if ((string)$p->enabled !== '1') {
                continue;
            }
            $id++;
            $ifids = self::csv($p->interfaces);
            $result[] = [
                'id' => $id,
                'uuid' => $uuid,
                'name' => (string)$p->name,
                'action' => (string)$p->action,
                'direction' => (string)$p->direction,
                'ifids' => $ifids,
                'countries' => array_map('strtoupper', self::csv($p->countries)),
                'exceptions' => self::csv($p->exceptions),
                'log' => (string)$p->log === '1',
                'table' => 'l7_geo_' . $id,
                'file' => '/var/db/layer7security/geo/policy_' . $id . '.txt',
            ];
        }
        return $result;
    }

    /** settings document read by the ICAP server and the Squid config writer */
    public static function inspection(array $general, array $policies)
    {
        $mdl = new Layer7Security();
        $rules = [];
        foreach ($policies as $p) {
            if (!empty($p['inspect']) && !empty($p['ai']) && $p['action'] !== 'block' && !empty($p['hosts'])) {
                $rules[] = ['ai' => $p['ai'], 'name' => $p['name'], 'domains' => $p['hosts'], 'sources' => $p['sources']];
            }
        }
        $d = $mdl->dlp;
        $av = $mdl->av;
        return [
            'enabled' => $general['dlpEnabled'],
            'categories' => ['card' => (string)$d->cardAction, 'id' => (string)$d->idAction,
                             'api_key' => (string)$d->keyAction, 'code' => (string)$d->codeAction],
            'codeMinLines' => (int)(string)$d->codeMinLines, 'failMode' => (string)$d->failMode,
            'maxBodyKb' => (int)(string)$d->maxBodyKb, 'blockMessage' => (string)$d->blockMessage,
            'rules' => $rules,
            'av' => [
                'enabled' => $general['avEnabled'], 'http' => $general['avHttp'],
                'https_domains' => $general['avHttpsAllowed'] ? $general['avHttpsDomains'] : [],
                'skip' => array_map('strtolower', self::csv($av->skipDomains)),
                'maxSizeMb' => (int)(string)$av->maxSizeMb, 'failMode' => (string)$av->failMode,
                'hashAction' => (string)$av->hashAction, 'yaraAction' => (string)$av->yaraAction,
                'useCloud' => (string)$av->useCloud === '1',
                'types' => ['executable' => (string)$av->executableAction, 'script' => (string)$av->scriptAction,
                            'package' => (string)$av->packageAction, 'archive' => (string)$av->archiveAction],
                'customHashes' => array_map('strtolower', self::csv($av->customHashes)),
                'feed' => ['url' => (string)$av->feedUrl, 'authKey' => (string)$av->feedAuthKey,
                           'hours' => (int)(string)$av->feedHours],
            ],
        ];
    }

    /** is the country database loaded (non-empty) */
    public static function geoDataReady()
    {
        return is_file('/var/db/layer7security/geo/v4.tsv') && filesize('/var/db/layer7security/geo/v4.tsv') > 0;
    }

    /** is the policy inside its schedule window right now (firewall local time) */
    public static function active(array $policy, $now = null)
    {
        $now = $now ?? time();
        if (!($policy['dayMask'] & (1 << (int)date('w', $now)))) {
            return false;
        }
        $toMin = function ($s) {
            $parts = explode(':', $s);
            return ((int)$parts[0]) * 60 + (int)($parts[1] ?? 0);
        };
        $start = $toMin($policy['start']);
        $end = $toMin($policy['end']);
        if ($start === $end) {
            return true;
        }
        $cur = (int)date('G', $now) * 60 + (int)date('i', $now);
        return $start < $end ? ($cur >= $start && $cur < $end) : ($cur >= $start || $cur < $end);
    }
}
