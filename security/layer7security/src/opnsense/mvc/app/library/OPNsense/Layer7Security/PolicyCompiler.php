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
        return [
            'enabled' => (string)$g->enabled === '1',
            'enforce' => (string)$g->enforce === '1',
            'devices' => $devices,
            'retention' => (int)(string)$g->retention,
            'flowTimeout' => (int)(string)$g->flowTimeout,
            'blockTtl' => (int)(string)$g->blockTtl,
            'dnsFilter' => (string)$g->dnsFilter === '1',
            'dnsMode' => (string)$g->dnsMode ?: 'nxdomain',
            'dnsCategories' => self::csv($g->dnsCategories),
            'dnsBlock' => array_map('strtolower', self::csv($g->dnsBlock)),
            'dnsAllow' => array_map('strtolower', self::csv($g->dnsAllow)),
            'feedUrl' => (string)$g->feedUrl,
        ];
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
            foreach (self::csv($p->users) as $uid) {
                $user = $mdl->getNodeByReference('users.user.' . $uid);
                if ($user !== null) {
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
            ];
        }
        return $result;
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
