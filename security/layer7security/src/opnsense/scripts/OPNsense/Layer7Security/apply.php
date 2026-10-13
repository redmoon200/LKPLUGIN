#!/usr/local/bin/php
<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Generate engine.conf, policies.conf and the Unbound DNS filter from the
 * model, then reload pf rules and (re)start or stop the engine.
 *
 *   apply.php            full apply
 *   apply.php --dns-only regenerate only the DNS filter (cron, schedules)
 *
 * Prints "OK" on success, an error message otherwise (read by the GUI).
 */

require_once('script/load_phalcon.php');

use OPNsense\Core\Backend;
use OPNsense\Layer7Security\PolicyCompiler;

const CONF_DIR = '/usr/local/etc/layer7security';
const DB_DIR = '/var/db/layer7security';
const LIST_DIR = '/var/db/layer7security/lists';
const SEED_DIR = '/usr/local/share/layer7security/seeds';
const UNBOUND_FILE = '/usr/local/etc/unbound.opnsense.d/layer7security.conf';
const MAX_ZONES = 400000;
const GEO_DIR = '/var/db/layer7security/geo';
const ARP_STATE = '/var/db/layer7security/arp_static.json';

function write_if_changed($path, $content, $mode = 0644)
{
    if (is_file($path) && file_get_contents($path) === $content) {
        return false;
    }
    $tmp = $path . '.tmp';
    file_put_contents($tmp, $content);
    chmod($tmp, $mode);
    rename($tmp, $path);
    return true;
}

function ensure_dirs()
{
    foreach ([CONF_DIR, DB_DIR, LIST_DIR] as $dir) {
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }
    }
}

function valid_domain($d)
{
    return (bool)preg_match('/^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$/', $d) && strpos($d, '..') === false;
}

/** domains of one DNS category: downloaded feed list merged with the seed list */
function category_domains($cat)
{
    if (!preg_match('/^[a-z]+$/', $cat)) {
        return [];
    }
    $domains = [];
    foreach ([LIST_DIR . "/$cat.txt", SEED_DIR . "/$cat.txt"] as $file) {
        if (!is_file($file)) {
            continue;
        }
        foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $line = strtolower(trim($line));
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if (valid_domain($line)) {
                $domains[$line] = true;
            }
        }
    }
    return $domains;
}

function filter_allowed(array $domains, array $allow)
{
    if (empty($allow)) {
        return $domains;
    }
    foreach (array_keys($domains) as $d) {
        foreach ($allow as $a) {
            if ($d === $a || substr($d, -strlen($a) - 1) === '.' . $a) {
                unset($domains[$d]);
                break;
            }
        }
    }
    return $domains;
}

function zone_lines(array $domains, $mode, &$count)
{
    $out = '';
    foreach (array_keys($domains) as $d) {
        if ($count >= MAX_ZONES) {
            break;
        }
        $count++;
        if ($mode === 'refuse') {
            $out .= "local-zone: \"$d.\" always_refuse\n";
        } elseif ($mode === 'null') {
            $out .= "local-zone: \"$d.\" redirect\n";
            $out .= "local-data: \"$d. 60 IN A 0.0.0.0\"\n";
            $out .= "local-data: \"$d. 60 IN AAAA ::\"\n";
        } else {
            $out .= "local-zone: \"$d.\" always_nxdomain\n";
        }
    }
    return $out;
}

/** zones that always resolve normally, even below a blocked parent (allow lists) */
function allow_lines(array $allow)
{
    $out = '';
    foreach (array_keys($allow) as $d) {
        $out .= "local-zone: \"$d.\" transparent\n";
    }
    return $out;
}

/** Google country domains that get safe search */
const SAFE_GOOGLE = ['com', 'co.uk', 'de', 'fr', 'es', 'it', 'nl', 'pl', 'ru', 'ca', 'com.au', 'co.in', 'co.jp', 'com.br',
    'com.mx', 'com.tr', 'co.za', 'se', 'no', 'fi', 'dk', 'at', 'ch', 'be', 'pt', 'gr', 'cz', 'ro', 'hu', 'ie', 'co.nz',
    'com.sg', 'com.hk', 'co.kr', 'com.ar', 'cl', 'com.co', 'com.pk', 'com.eg', 'com.ng', 'co.il', 'ae', 'com.sa', 'ua'];

/** Unbound lines that force safe search / YouTube restricted mode with CNAME answers */
function safe_search_lines($general)
{
    $out = '';
    $cname = function ($name, $target) {
        return "local-zone: \"$name.\" redirect\nlocal-data: \"$name. 3600 IN CNAME $target.\"\n";
    };
    if ($general['safeSearch']) {
        foreach (SAFE_GOOGLE as $tld) {
            $out .= $cname('www.google.' . $tld, 'forcesafesearch.google.com');
        }
        $out .= $cname('www.bing.com', 'strict.bing.com');
        $out .= $cname('duckduckgo.com', 'safe.duckduckgo.com');
        $out .= $cname('www.duckduckgo.com', 'safe.duckduckgo.com');
        $out .= $cname('pixabay.com', 'safesearch.pixabay.com');
    }
    if ($general['youtubeMode'] !== 'off') {
        $target = $general['youtubeMode'] === 'strict' ? 'restrict.youtube.com' : 'restrictmoderate.youtube.com';
        foreach (['www.youtube.com', 'm.youtube.com', 'youtubei.googleapis.com', 'youtube.googleapis.com',
                  'www.youtube-nocookie.com'] as $h) {
            $out .= $cname($h, $target);
        }
    }
    return $out;
}

/** build the Unbound include; returns true when the file changed */
function build_dns($general, $policies)
{
    $path = UNBOUND_FILE;
    $cfs = $general['dnsFilter'];
    $web = false;
    foreach ($policies as $p) {
        if (($p['module'] ?? '') === 'web' && !empty($p['dnsDomains'])) {
            $web = true;
        }
    }
    $safe = $general['safeSearch'] || $general['youtubeMode'] !== 'off';
    if (!$general['enabled'] || (!$cfs && !$web && !$safe)) {
        if (is_file($path)) {
            unlink($path);
            return true;
        }
        return false;
    }
    $mode = $general['dnsMode'];
    $count = 0;
    $global = [];
    $allowGlobal = [];
    if ($cfs) {
        foreach ($general['dnsCategories'] as $cat) {
            $global += category_domains($cat);
        }
        foreach ($general['dnsBlock'] as $d) {
            if (valid_domain($d)) {
                $global[$d] = true;
            }
        }
    }
    foreach ($general['dnsAllow'] as $d) {
        if ($cfs && valid_domain($d)) {
            $allowGlobal[$d] = true;
        }
    }
    /* per source-network groups (policies that are in their schedule window) */
    $byNet = [];
    $allowByNet = [];
    foreach ($policies as $p) {
        $isWeb = ($p['module'] ?? '') === 'web';
        if ((!$isWeb && !$cfs) || (empty($p['dnsCategories']) && empty($p['dnsDomains']))) {
            continue;
        }
        if (!in_array($p['action'], ['block', 'allow'], true) || !PolicyCompiler::active($p)) {
            continue;
        }
        /* a rule for signed-in users without device addresses cannot be told apart by DNS: never widen it to everybody */
        if (!empty($p['restrict']) && empty($p['sources'])) {
            continue;
        }
        $set = [];
        foreach ($p['dnsCategories'] as $cat) {
            $set += category_domains($cat);
        }
        foreach ($p['dnsDomains'] as $d) {
            if (valid_domain($d)) {
                $set[$d] = true;
            }
        }
        if ($p['action'] === 'allow') {
            if (empty($p['sources'])) {
                $allowGlobal += $set;
            }
            foreach ($p['sources'] as $net) {
                $allowByNet[$net] = ($allowByNet[$net] ?? []) + $set;
            }
            continue;
        }
        if (empty($p['sources'])) {
            $global += $set;
            continue;
        }
        foreach ($p['sources'] as $net) {
            $byNet[$net] = ($byNet[$net] ?? []) + $set;
        }
    }
    foreach (array_keys($allowByNet) as $net) {
        $byNet[$net] = $byNet[$net] ?? [];
    }
    $global = filter_allowed($global, array_keys($allowGlobal));
    /* the filter's decisions are logged (the CFS and Web Control activity lists read them) */
    $conf = "# generated by os-layer7security, do not edit\nserver:\nlog-local-actions: yes\nverbosity: 1\n";
    $views = '';
    $n = 0;
    foreach ($byNet as $net => $set) {
        $n++;
        $allowHere = $allowGlobal + ($allowByNet[$net] ?? []);
        $set = filter_allowed($set, array_keys($allowHere));
        $conf .= "access-control-view: $net l7v_$n\n";
        $views .= "view:\nname: \"l7v_$n\"\nview-first: yes\n" . zone_lines($set, $mode, $count) .
            allow_lines($allowHere) . "\n";
    }
    $conf .= zone_lines($global, $mode, $count) . allow_lines($allowGlobal) . safe_search_lines($general) . "\n" . $views;
    return write_if_changed($path, $conf);
}

/**
 * Permanent ARP entries for bound addresses (when enabled): the firewall then
 * ignores forged ARP replies for them. Entries removed from the bindings are
 * deleted again (tracked in a state file).
 */
function sync_static_arp($general, $bindings)
{
    $old = json_decode(@file_get_contents(ARP_STATE), true);
    $old = is_array($old) ? $old : [];
    $want = [];
    if ($general['enabled'] && $general['macMode'] !== 'off' && $general['macStaticArp']) {
        foreach ($bindings as $b) {
            if ($b['ip'] !== '' && filter_var($b['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                $want[$b['ip']] = $b['mac'];
            }
        }
    }
    foreach ($old as $ip => $mac) {
        if (!isset($want[$ip]) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            exec('/usr/sbin/arp -d ' . escapeshellarg($ip) . ' 2>&1');
        }
    }
    foreach ($want as $ip => $mac) {
        exec('/usr/sbin/arp -S ' . escapeshellarg($ip) . ' ' . escapeshellarg($mac) . ' 2>&1');
    }
    file_put_contents(ARP_STATE, json_encode($want));
}

/**
 * Web Control IP rules: one table file per group of client sources (the pf hook
 * registers the tables from these files). Returns the networks that were not
 * blocked at the previous apply, so their open connections can be cut.
 */
function sync_web_ip($general)
{
    $state = DB_DIR . '/webip_state.json';
    $old = json_decode(@file_get_contents($state), true);
    $old = is_array($old) ? $old : [];
    $groups = $general['enabled'] ? PolicyCompiler::webIpGroups($general) : [];
    $keep = [];
    $new = [];
    foreach ($groups as $g) {
        write_if_changed($g['file'], implode("\n", $g['entries']) . "\n");
        $keep[$g['file']] = true;
        foreach ($g['blocked'] as $net) {
            $new[$net] = true;
        }
    }
    foreach (glob(DB_DIR . '/webip_[0-9]*.txt') ?: [] as $file) {
        if (!isset($keep[$file])) {
            unlink($file);
        }
    }
    file_put_contents($state, json_encode(array_keys($new)));
    return array_values(array_diff(array_keys($new), $old));
}

/** make sure every enabled threat list has a file (empty until the first download) */
function sync_threat_files($general)
{
    $dir = DB_DIR . '/threat';
    if (!is_dir($dir)) {
        mkdir($dir, 0750, true);
    }
    foreach (PolicyCompiler::threatLists($general) as $t) {
        if (!is_file($t['file'])) {
            touch($t['file']);
        }
    }
}

/** earliest expiry of a temporary Web Control rule, read by the once-a-minute expiry job */
function write_expiry()
{
    $next = 0;
    foreach (PolicyCompiler::webRules() as $r) {
        if ($r['expires'] > 0 && ($next === 0 || $r['expires'] < $next)) {
            $next = $r['expires'];
        }
    }
    write_if_changed(DB_DIR . '/web_expiry', $next . "\n");
}

/**
 * Sign-in portal: settings, service and the "ready" flag the pf hook looks at.
 * Returns an error text, or '' when the portal runs (or sign-in is off).
 */
function sync_portal($backend, $portal, array $policies)
{
    $ready = DB_DIR . '/auth_ready';
    $map = $portal === null ? [] : PolicyCompiler::userTables($policies);
    write_if_changed(CONF_DIR . '/user_tables.json', json_encode((object)$map));
    if ($portal === null) {
        @unlink($ready);
        write_if_changed('/etc/rc.conf.d/layer7security_portal', 'layer7security_portal_enable="NO"' . PHP_EOL);
        $backend->configdRun('layer7security portal-stop');
        file_put_contents(DB_DIR . '/sessions.tsv', '');
        return '';
    }
    $changed = write_if_changed(CONF_DIR . '/portal.json', json_encode($portal, JSON_PRETTY_PRINT), 0640);
    write_if_changed('/etc/rc.conf.d/layer7security_portal', 'layer7security_portal_enable="YES"' . PHP_EOL);
    foreach (array_merge(['auth_ok'], array_map(function ($id) {
        return 'usr_' . $id;
    }, array_keys($map))) as $name) {
        if (!is_file(DB_DIR . "/$name.txt")) {
            touch(DB_DIR . "/$name.txt");
        }
    }
    $running = strpos(trim($backend->configdRun('layer7security portal-status')), 'is running') !== false;
    if ($changed || !$running) {
        $backend->configdRun('layer7security portal-restart');
    }
    $up = false;
    for ($i = 0; $i < 20 && !$up; $i++) {
        $fp = @fsockopen('127.0.0.1', 8081, $errno, $errstr, 1);
        if ($fp) {
            fclose($fp);
            $up = true;
        } else {
            usleep(250000);
        }
    }
    if (!$up) {
        @unlink($ready);
        return 'The sign-in portal did not start: ' . trim($backend->configdRun('layer7security portal-status')) .
            ' (see /var/log/l7portal.log). Sign-in is not enforced.';
    }
    $backend->configdRun('layer7security auth-sync');
    touch($ready);
    return '';
}

/** drop the connections that already use a newly blocked network */
function kill_blocked_states(array $nets)
{
    foreach ($nets as $net) {
        if (PolicyCompiler::normalizeIp($net) !== null) {
            $any = strpos($net, ':') === false ? '0.0.0.0/0' : '::/0';
            exec('/sbin/pfctl -k ' . escapeshellarg($any) . ' -k ' . escapeshellarg($net) . ' 2>&1');
            exec('/sbin/pfctl -k ' . escapeshellarg($net) . ' 2>&1');
        }
    }
}

function main($argv)
{
    ensure_dirs();
    $general = PolicyCompiler::general();
    $policies = PolicyCompiler::policies();
    $bindings = PolicyCompiler::bindings();
    $backend = new Backend();

    /* decrypting and scanning content also needs the notice (and the CA on the clients) */
    if ($general['enabled'] && ($general['dlpEnabled'] || $general['dpiEnabled'] || $general['avHttpsAllowed'] || ($general['avEnabled'] && !empty($general['avHttpsDomains']))) && !$general['privacyAck']) {
        return 'TLS inspection (DPI-SSL, AI content inspection or antivirus on HTTPS) is enabled but the privacy notice has not been acknowledged (AI Audit > Privacy).';
    }

    /* logging what people do with AI services needs the privacy notice to be acknowledged first */
    if ($general['enabled'] && $general['auditEnabled'] && !$general['privacyAck']) {
        return 'AI audit logging is enabled but the privacy notice has not been acknowledged (AI Audit > Privacy).';
    }

    if (count($policies) > 240) {
        return 'Too many rules for the engine (' . count($policies) . ', limit 240). Use the content filter categories for long website lists.';
    }

    if (in_array('--dns-only', $argv)) {
        if (build_dns($general, $policies)) {
            $backend->configdRun('unbound restart');
        }
        return 'OK';
    }

    /* engine.conf */
    $conf = "# generated by os-layer7security, do not edit\n";
    foreach ($general['devices'] as $dev) {
        $conf .= "interface=$dev\n";
    }
    $conf .= 'retention_days=' . $general['retention'] . "\n";
    $conf .= 'flow_timeout=' . $general['flowTimeout'] . "\n";
    $conf .= 'block_ttl=' . $general['blockTtl'] . "\n";
    $conf .= 'enforce=' . ($general['enforce'] ? 1 : 0) . "\n";
    $conf .= "db=" . DB_DIR . "/l7.db\n";
    $conf .= "policies=" . CONF_DIR . "/policies.conf\n";
    $conf .= 'ai_inspect=' . (!empty($general['aiInspect']) ? 1 : 0) . PHP_EOL;
    $conf .= 'ai_quic=' . ['off' => 0, 'ai' => 1, 'all' => 2][$general['aiQuic']] . PHP_EOL;
    $conf .= 'bindings=' . CONF_DIR . '/bindings.conf' . PHP_EOL;
    $conf .= 'sessions=' . DB_DIR . '/sessions.tsv' . PHP_EOL;
    $conf .= 'geo_dir=' . GEO_DIR . PHP_EOL;
    foreach ($general['ifids'] as $ifid) {
        $net = PolicyCompiler::network($ifid);
        if ($net !== null) {
            $conf .= 'net=' . $net . PHP_EOL;
        }
    }
    write_if_changed(CONF_DIR . '/engine.conf', $conf);

    /* MAC bindings for the engine's spoof detection: mac ip device name */
    $blines = '# generated by os-layer7security, do not edit' . PHP_EOL;
    foreach ($bindings as $b) {
        $blines .= implode(chr(9), [$b['mac'], $b['ip'] === '' ? '-' : $b['ip'],
            $b['device'] ?? '-', preg_replace('/[[:cntrl:]]/', ' ', $b['name'])]) . PHP_EOL;
    }
    write_if_changed(CONF_DIR . '/bindings.conf', $blines);

    /* GeoIP: policy list for geo.py, then rebuild the tables when data exists */
    write_if_changed(CONF_DIR . '/geo_policies.json', json_encode(PolicyCompiler::geoPolicies()));
    if ($general['geoEnabled'] && PolicyCompiler::geoDataReady()) {
        exec('/usr/local/opnsense/scripts/OPNsense/Layer7Security/geo.py build 2>&1');
    }
    sync_static_arp($general, $bindings);
    $webIpKill = sync_web_ip($general);
    sync_threat_files($general);
    write_expiry();

    /* policies.conf, one TAB separated line per policy */
    $lines = "# generated by os-layer7security, do not edit\n";
    foreach ($policies as $p) {
        $lines .= implode("\t", [
            $p['id'],
            preg_replace('/[\t\r\n]/', ' ', $p['name']),
            $p['action'],
            empty($p['sources']) ? '-' : implode(',', $p['sources']),
            empty($p['apps']) ? '-' : implode(',', $p['apps']),
            empty($p['cats']) ? '-' : implode(',', $p['cats']),
            empty($p['hosts']) ? '-' : implode(',', $p['hosts']),
            $p['dayMask'],
            $p['start'],
            $p['end'],
            implode(',', array_filter([
                !empty($p['ai']) ? 'ai=' . $p['ai'] : '',
                !empty($p['inspect']) ? 'inspect' : '',
                !empty($p['quic']) ? 'quic' : '',
                !empty($p['restrict']) ? 'restrict' : '',
                !empty($p['users']) ? 'users=' . implode('|', $p['users']) : '',
            ])) ?: '-',
        ]) . "\n";
    }
    write_if_changed(CONF_DIR . '/policies.conf', $lines);

    /* rc.conf.d enable flag */
    write_if_changed('/etc/rc.conf.d/layer7security', 'layer7security_enable="' . ($general['enabled'] ? 'YES' : 'NO') . "\"\n");

    /* catalog for the GUI selectors (first run) */
    if (!is_file(CONF_DIR . '/apps.json')) {
        $backend->configdRun('layer7security catalog');
    }

    /* sign-in portal first: the pf rules only exist when it is up */
    $authError = sync_portal($backend, PolicyCompiler::portal($general), $policies);

    /* cloud data that is enabled but not downloaded yet (category lists, threat lists, hashes, signatures) */
    if ($general['enabled'] && $general['feedUrl'] !== '') {
        $backend->configdRun('layer7security feed-fill');
    }

    /* pf tables and rules */
    $backend->configdRun('filter reload');
    kill_blocked_states($webIpKill);

    /* DNS filter */
    if (build_dns($general, $policies)) {
        $backend->configdRun('unbound restart');
    }

    /* inspection proxy: ICAP server + Squid, restarted only when their settings changed */
    $inspection = json_encode(PolicyCompiler::inspection($general, $policies), JSON_PRETTY_PRINT);
    $changed = write_if_changed(CONF_DIR . '/inspection.json', $inspection, 0600);
    $needHttps = !empty($general['aiInspect']);
    $proxyOn = $general['enabled'] && $general['proxyNeeded'];
    write_if_changed('/etc/rc.conf.d/layer7security_proxy', 'layer7security_proxy_enable="' . ($proxyOn ? 'YES' : 'NO') . '"' . PHP_EOL);
    if ($proxyOn) {
        if ($needHttps || $general['avHttpsAllowed'] || $general['dpiAllowed']) {
            $ca = json_decode(trim($backend->configdRun('layer7security inspection-ca-init')), true);
            if (empty($ca['created']) && !empty($ca['error'])) {
                return 'cannot create the inspection CA: ' . $ca['error'];
            }
        }
        $chk = json_decode(trim($backend->configdRun('layer7security inspection-ca-check')), true);
        if (!empty($chk['uncovered'])) {
            return 'The inspection CA is not allowed to sign for ' . implode(', ', array_slice($chk['uncovered'], 0, 5)) .
                '. Replace the CA (DPI-SSL > Certificate) and install the new certificate on the clients, or remove these sites.';
        }
        $before = is_file(CONF_DIR . '/squid.conf') ? md5_file(CONF_DIR . '/squid.conf') : '';
        $backend->configdRun('layer7security inspection-write');
        $changed = $changed || $before !== (is_file(CONF_DIR . '/squid.conf') ? md5_file(CONF_DIR . '/squid.conf') : '');
        $running = strpos(trim($backend->configdRun('layer7security proxy-status')), 'is running') !== false;
        /* a replaced CA must be loaded by the proxy: remember which certificate it was started with */
        $caFile = DB_DIR . '/ca/ca.crt';
        $caSig = is_file($caFile) ? md5_file($caFile) : '';
        $caSeen = trim((string)@file_get_contents(DB_DIR . '/ca/applied.md5'));
        if ($caSig !== '' && $caSig !== $caSeen) {
            $changed = true;
        }
        if ($changed || !$running) {
            $backend->configdRun('layer7security proxy-restart');
            if ($caSig !== '') {
                @file_put_contents(DB_DIR . '/ca/applied.md5', $caSig . PHP_EOL);
            }
        }
    } else {
        $backend->configdRun('layer7security proxy-stop');
    }

    /* engine */
    $backend->configdRun('layer7security stop');
    if ($general['enabled']) {
        $backend->configdRun('layer7security start');
        sleep(1);
        $status = trim($backend->configdRun('layer7security status'));
        if (strpos($status, 'is running') === false) {
            return 'engine did not start: ' . trim($backend->configdRun('layer7security log-tail'));
        }
    }
    if ($authError !== '') {
        return $authError;
    }
    /* start the audit trail from the moment it is enabled (older engine events are never imported) */
    if ($general['auditEnabled'] && $general['privacyAck']) {
        $backend->configdRun('layer7security audit-ingest');
    }
    return 'OK';
}

echo main($argv) . "\n";
