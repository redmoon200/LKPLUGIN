#!/usr/bin/env python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# State of the cloud server (SQLite): who pulled what, which firewalls checked in,
# the licenses that were issued, dashboard sessions and settings. Shared by the
# feed server and the dashboard.

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time

ROOT = os.environ.get('L7_CLOUD_ROOT', '/var/lib/l7cloud')
DB = os.path.join(ROOT, 'state.db')
KEEP_REQUEST_DAYS = 30

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS requests(
  id INTEGER PRIMARY KEY, ts INTEGER, ip TEXT, method TEXT, path TEXT, status INTEGER, bytes INTEGER, ua TEXT);
CREATE INDEX IF NOT EXISTS requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS requests_ip ON requests(ip, ts);
CREATE TABLE IF NOT EXISTS clients(
  install_id TEXT PRIMARY KEY, first_seen INTEGER, last_seen INTEGER, last_ip TEXT, hostname TEXT, version TEXT,
  os TEXT, key_id TEXT, lic_state TEXT, checkins INTEGER DEFAULT 0, info TEXT);
CREATE TABLE IF NOT EXISTS licenses(
  key_id TEXT PRIMARY KEY, key TEXT NOT NULL, type TEXT, customer TEXT, note TEXT, issued INTEGER, expires INTEGER,
  bound_install TEXT, created INTEGER, source TEXT, revoked INTEGER DEFAULT 0, revoked_ts INTEGER,
  replacement_key TEXT);
CREATE TABLE IF NOT EXISTS trials(install_id TEXT PRIMARY KEY, key_id TEXT, ts INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, created INTEGER, expires INTEGER, ip TEXT);
CREATE TABLE IF NOT EXISTS logins(id INTEGER PRIMARY KEY, ts INTEGER, ip TEXT, ok INTEGER);
"""


def connect():
    os.makedirs(ROOT, exist_ok=True)
    con = sqlite3.connect(DB, timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    try:
        os.chmod(DB, 0o600)
    except OSError:
        pass
    return con


def get_setting(con, key, default=None):
    row = con.execute('SELECT v FROM settings WHERE k=?', (key,)).fetchone()
    return row['v'] if row else default


def set_setting(con, key, value):
    with con:
        con.execute('REPLACE INTO settings(k,v) VALUES(?,?)', (key, value))


# ---- admin password: PBKDF2, never stored in clear
def hash_password(password, salt=None, rounds=240000):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), rounds).hex()
    return '%d$%s$%s' % (rounds, salt, h)


def check_password(password, stored):
    try:
        rounds, salt, h = stored.split('$')
        calc = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(rounds)).hex()
        return hmac.compare_digest(calc, h)
    except (ValueError, AttributeError):
        return False


# ---- request log and firewalls
def log_request(ip, method, path, status, size, ua=''):
    try:
        con = connect()
        with con:
            con.execute('INSERT INTO requests(ts,ip,method,path,status,bytes,ua) VALUES(?,?,?,?,?,?,?)',
                        (int(time.time()), ip[:64], method[:8], path[:200], int(status), int(size), (ua or '')[:120]))
        con.close()
    except sqlite3.Error:
        pass


def prune():
    con = connect()
    with con:
        con.execute('DELETE FROM requests WHERE ts < ?', (int(time.time()) - KEEP_REQUEST_DAYS * 86400,))
        con.execute('DELETE FROM sessions WHERE expires < ?', (int(time.time()),))
        con.execute('DELETE FROM logins WHERE ts < ?', (int(time.time()) - 86400,))
    con.close()


def note_client(con, install_id, ip, hostname='', version='', os_name='', key_id='', lic_state='', info=None):
    now = int(time.time())
    row = con.execute('SELECT install_id FROM clients WHERE install_id=?', (install_id,)).fetchone()
    with con:
        if row is None:
            con.execute('INSERT INTO clients(install_id,first_seen,last_seen,last_ip,hostname,version,os,key_id,lic_state,'
                        'checkins,info) VALUES(?,?,?,?,?,?,?,?,?,1,?)',
                        (install_id, now, now, ip, hostname[:64], version[:20], os_name[:40], key_id, lic_state,
                         json.dumps(info or {})))
        else:
            con.execute("UPDATE clients SET last_seen=?, last_ip=?, hostname=COALESCE(NULLIF(?,''),hostname),"
                        " version=COALESCE(NULLIF(?,''),version), os=COALESCE(NULLIF(?,''),os), key_id=?, lic_state=?,"
                        " checkins=checkins+1, info=? WHERE install_id=?",
                        (now, ip, hostname[:64], version[:20], os_name[:40], key_id, lic_state, json.dumps(info or {}),
                         install_id))
