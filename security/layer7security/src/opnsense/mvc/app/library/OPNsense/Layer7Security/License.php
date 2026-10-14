<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security;

/**
 * License of the plugin. A key is a signed record (type, issue date, length, key id,
 * optional binding to this firewall); the signature is checked with the vendor's
 * public key, which is the only thing shipped here. The same format is produced by
 * cloud/server/licenselib.py.
 *
 *   trial 30 days | year 365 days | lifetime (never expires)
 *
 * Without a valid license the plugin is locked: its pages show the license screen,
 * and the protection is switched off (the network itself keeps working).
 */
class License
{
    /** vendor public key (Ed25519, raw 32 bytes, base64): set by the cloud server dashboard (Settings) */
    public const PUBKEY_B64 = '2kJDQOe55A8lmYYo4Cf5EsRi/8GPXnqHLOqDt9Ed1lY=';

    public const DIR = '/var/db/layer7security';
    public const FILE = '/var/db/layer7security/license.json';
    public const SEEN = '/var/db/layer7security/license_seen.json';
    public const REVOKED = '/var/db/layer7security/license_revoked.json';
    public const STATE = '/var/db/layer7security/license_state.json';
    private const EPOCH = 1577836800;
    private const PAYLOAD = 22;
    private const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    private const TYPES = [1 => 'trial', 2 => 'year', 4 => 'lifetime'];
    public const LABELS = ['trial' => 'Trial (30 days)', 'year' => 'Standard (1 year)', 'lifetime' => 'Lifetime'];
    private const OPENSSL = '/usr/bin/openssl';

    private static $cache = null;

    /** installation id of this firewall: 1234-ABCD-5678-EF01 (from the system's host uuid) */
    public static function installId()
    {
        static $id = null;
        if ($id === null) {
            $uuid = trim((string)@shell_exec('/sbin/sysctl -n kern.hostuuid 2>/dev/null'));
            if ($uuid === '') {
                $uuid = trim((string)@file_get_contents('/etc/hostid'));
            }
            $hex = strtoupper(substr(hash('sha256', 'L7INST1|' . $uuid), 0, 16));
            $id = implode('-', str_split($hex, 4));
        }
        return $id;
    }

    private static function bindHash($installId)
    {
        return substr(hash('sha256', 'L7BIND1|' . strtoupper(preg_replace('/[^0-9A-Fa-f]/', '', $installId)), true), 0, 8);
    }

    private static function b32decode($text)
    {
        $bits = '';
        foreach (str_split($text) as $ch) {
            $p = strpos(self::B32, $ch);
            if ($p === false) {
                return false;
            }
            $bits .= str_pad(decbin($p), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $b) {
            if (strlen($b) < 8) {
                break;
            }
            $out .= chr(bindec($b));
        }
        return $out;
    }

    public static function normalize($text)
    {
        return preg_replace('/[^A-Z2-7]/', '', strtoupper((string)$text));
    }

    private static function publicPem()
    {
        $der = hex2bin('302a300506032b6570032100') . base64_decode(self::PUBKEY_B64, true);
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /** Ed25519 check through the openssl command line (no PHP extension needed) */
    private static function verifySignature($payload, $sig)
    {
        if (!is_dir(self::DIR . '/tmp')) {
            @mkdir(self::DIR . '/tmp', 0700, true);
        }
        $base = tempnam(self::DIR . '/tmp', 'lic');
        if ($base === false) {
            return false;
        }
        $files = [$base . '.m', $base . '.s', $base . '.p'];
        file_put_contents($files[0], "L7LIC1\0" . $payload);
        file_put_contents($files[1], $sig);
        file_put_contents($files[2], self::publicPem());
        $proc = @proc_open([self::OPENSSL, 'pkeyutl', '-verify', '-pubin', '-inkey', $files[2], '-rawin', '-in', $files[0],
            '-sigfile', $files[1]], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $ok = false;
        if (is_resource($proc)) {
            stream_get_contents($pipes[1]);
            stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $ok = proc_close($proc) === 0;
        }
        foreach (array_merge([$base], $files) as $f) {
            @unlink($f);
        }
        return $ok;
    }

    /** decode and verify a key text; ['ok' => false, 'error' => ...] or the key's fields */
    public static function parse($keyText)
    {
        $raw = self::b32decode(self::normalize($keyText));
        if ($raw === false || strlen($raw) !== self::PAYLOAD + 64) {
            return ['ok' => false, 'error' => 'That does not look like a license key.'];
        }
        $payload = substr($raw, 0, self::PAYLOAD);
        if (!self::verifySignature($payload, substr($raw, self::PAYLOAD))) {
            return ['ok' => false, 'error' => 'Invalid license key (the signature check failed).'];
        }
        if (ord($payload[0]) !== 1 || !isset(self::TYPES[ord($payload[1])])) {
            return ['ok' => false, 'error' => 'Unsupported license key.'];
        }
        $type = self::TYPES[ord($payload[1])];
        $f = unpack('nd/ndur', substr($payload, 2, 4));
        $days = (int)$f['dur'];
        if (($type === 'lifetime') !== ($days === 0)) {
            return ['ok' => false, 'error' => 'Invalid license duration.'];
        }
        $issued = self::EPOCH + (int)$f['d'] * 86400;
        $bind = substr($payload, 14, 8);
        return [
            'ok' => true, 'type' => $type, 'label' => self::LABELS[$type], 'issued' => $issued, 'days' => $days,
            'expires' => $type === 'lifetime' ? null : $issued + $days * 86400,
            'key_id' => strtoupper(bin2hex(substr($payload, 6, 8))), 'bound' => $bind !== str_repeat("\0", 8),
            'bind' => bin2hex($bind), 'key' => implode('-', str_split(self::normalize($keyText), 5)),
        ];
    }

    private static function readJson($file)
    {
        $d = json_decode((string)@file_get_contents($file), true);
        return is_array($d) ? $d : [];
    }

    private static function writeJson($file, array $data)
    {
        if (!is_dir(self::DIR)) {
            @mkdir(self::DIR, 0750, true);
        }
        $tmp = $file . '.tmp';
        file_put_contents($tmp, json_encode($data));
        chmod($tmp, 0600);
        rename($tmp, $file);
    }

    private static function seenMac($ts)
    {
        return hash_hmac('sha256', 'seen|' . $ts, 'L7SEEN1|' . self::installId());
    }

    /** the clock must not run backwards (dated licenses only): the last time we saw is kept with a MAC */
    private static function lastSeen()
    {
        $d = self::readJson(self::SEEN);
        if (isset($d['ts'], $d['mac']) && hash_equals(self::seenMac((int)$d['ts']), (string)$d['mac'])) {
            return (int)$d['ts'];
        }
        return 0;
    }

    /** the vendor's server confirmed that the clock is right: forget a "last seen" time that lies in the future */
    public static function resetSeen()
    {
        self::writeJson(self::SEEN, ['ts' => time(), 'mac' => self::seenMac(time())]);
        self::$cache = null;
    }

    private static function touchSeen($now)
    {
        if ($now > self::lastSeen()) {
            self::writeJson(self::SEEN, ['ts' => $now, 'mac' => self::seenMac($now)]);
        }
    }

    /**
     * State of the license: none, valid, expired, invalid, wrongmachine, revoked or rollback.
     * The result also carries what the pages show (type, expiry, days left, install id).
     */
    public static function status($force = false)
    {
        if (self::$cache !== null && !$force) {
            return self::$cache;
        }
        $now = time();
        $out = ['state' => 'none', 'valid' => false, 'install_id' => self::installId(), 'message' => 'There is no license yet.',
                'type' => '', 'label' => '', 'expires' => null, 'days_left' => null, 'key_id' => '', 'warn' => false];
        $store = self::readJson(self::FILE);
        $key = (string)($store['key'] ?? '');
        if ($key !== '') {
            $info = null;
            // verify again at most every ten minutes; between, the stored result is used
            if (!$force && !empty($store['info']) && ($now - (int)($store['verified'] ?? 0)) < 600 && ($store['key_hash'] ?? '') === md5($key)) {
                $info = $store['info'];
            } else {
                $info = self::parse($key);
                $store['info'] = $info;
                $store['verified'] = $now;
                $store['key_hash'] = md5($key);
                self::writeJson(self::FILE, $store);
            }
            if (empty($info['ok'])) {
                $out['state'] = 'invalid';
                $out['message'] = $info['error'] ?? 'The license key is not valid.';
            } else {
                $out = array_merge($out, ['type' => $info['type'], 'label' => $info['label'], 'expires' => $info['expires'],
                    'key_id' => $info['key_id'], 'issued' => $info['issued'], 'bound' => $info['bound'],
                    'customer' => (string)($store['customer'] ?? '')]);
                $revoked = self::readJson(self::REVOKED);
                if ($info['bound'] && $info['bind'] !== bin2hex(self::bindHash(self::installId()))) {
                    $out['state'] = 'wrongmachine';
                    $out['message'] = 'This key was issued for another firewall.';
                } elseif (!empty($revoked['key_id']) && $revoked['key_id'] === $info['key_id']) {
                    $out['state'] = 'revoked';
                    $out['message'] = 'This license was withdrawn by the vendor.';
                } elseif ($info['expires'] !== null && $info['expires'] <= $now) {
                    $out['state'] = 'expired';
                    $out['message'] = 'The license has expired.';
                } elseif ($info['expires'] !== null && $now + 3600 * 24 < self::lastSeen()) {
                    $out['state'] = 'rollback';
                    $out['message'] = 'The clock of this firewall is behind: correct the date and time.';
                } else {
                    $out['state'] = 'valid';
                    $out['valid'] = true;
                    $out['message'] = $info['expires'] === null ? 'Lifetime license.' : 'License is active.';
                    if ($info['expires'] !== null) {
                        $out['days_left'] = (int)floor(($info['expires'] - $now) / 86400);
                        $out['warn'] = $out['days_left'] <= 14;
                    }
                    if ($info['expires'] !== null) {
                        self::touchSeen($now);
                    }
                }
            }
        }
        self::$cache = $out;
        /* a small snapshot for the scripts that cannot load this class (the downloaders): rewritten when it changes or gets old */
        $prev = self::readJson(self::STATE);
        if (($prev['state'] ?? '') !== $out['state'] || ($prev['key_id'] ?? '') !== $out['key_id'] || $now - (int)($prev['checked'] ?? 0) > 60) {
            $snapshot = $out;
            $snapshot['checked'] = $now;
            self::writeJson(self::STATE, $snapshot);
        }
        return $out;
    }

    public static function locked()
    {
        return !self::status()['valid'];
    }

    /** store a key; a running license is only replaced by one that lasts longer, a lifetime license never */
    public static function activate($keyText, $customer = '')
    {
        $info = self::parse($keyText);
        if (empty($info['ok'])) {
            return ['ok' => false, 'message' => $info['error']];
        }
        if ($info['bound'] && $info['bind'] !== bin2hex(self::bindHash(self::installId()))) {
            return ['ok' => false, 'message' => 'This key was issued for another firewall (installation id ' . self::installId() . ').'];
        }
        if ($info['expires'] !== null && $info['expires'] <= time()) {
            return ['ok' => false, 'message' => 'This key has already expired.'];
        }
        $cur = self::status(true);
        if ($cur['valid']) {
            if ($cur['type'] === 'lifetime') {
                return ['ok' => false, 'message' => 'A lifetime license is active and cannot be replaced.'];
            }
            if ($info['expires'] !== null && $info['expires'] <= $cur['expires']) {
                return ['ok' => false, 'message' => 'The new key must run longer than the current one (it ends ' . gmdate('Y-m-d', $cur['expires']) . ').'];
            }
        }
        $revoked = self::readJson(self::REVOKED);
        if (!empty($revoked['key_id']) && $revoked['key_id'] === $info['key_id']) {
            @unlink(self::REVOKED);
        }
        self::writeJson(self::FILE, ['key' => $info['key'], 'activated' => time(), 'customer' => $customer, 'info' => $info,
            'verified' => time(), 'key_hash' => md5($info['key'])]);
        self::$cache = null;
        return ['ok' => true, 'message' => $info['label'] . ' license activated.', 'status' => self::status(true)];
    }

    public static function remove()
    {
        @unlink(self::FILE);
        @unlink(self::REVOKED);
        self::$cache = null;
    }

    /** the vendor's server withdrew (or reinstated) the key */
    public static function setRevoked($keyId, $revoked)
    {
        if ($revoked) {
            self::writeJson(self::REVOKED, ['key_id' => $keyId, 'ts' => time()]);
        } else {
            @unlink(self::REVOKED);
        }
        self::$cache = null;
    }

    public static function currentKey()
    {
        return (string)(self::readJson(self::FILE)['key'] ?? '');
    }
}
