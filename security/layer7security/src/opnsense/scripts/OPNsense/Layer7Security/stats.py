#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Read-only queries over the engine's SQLite database; prints JSON.
#   stats.py summary|apps|categories|clients|timeline|blocks PERIOD
#   stats.py flows ROWS OFFSET PERIOD all|blocked PHRASE|-
#   stats.py events LIMIT

import json
import os
import re
import sqlite3
import sys
import time

DB = '/var/db/layer7security/l7.db'
STATUS = '/var/run/layer7security/status.json'
PERIODS = (300, 3600, 21600, 86400, 604800)


def connect():
    if not os.path.exists(DB):
        return None
    con = sqlite3.connect('file:%s?mode=ro' % DB, uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    return con


def rows(con, sql, args=()):
    return [dict(r) for r in con.execute(sql, args).fetchall()]


def to_int(value, default, lo=None, hi=None):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    if lo is not None and value < lo:
        return lo
    if hi is not None and value > hi:
        return hi
    return value


def summary(con, since):
    r = con.execute(
        "SELECT COUNT(*) AS flows, COALESCE(SUM(bytes_up),0) AS up, COALESCE(SUM(bytes_down),0) AS down,"
        " COUNT(DISTINCT client) AS clients, COUNT(DISTINCT app) AS apps,"
        " SUM(action='block') AS blocked FROM flows WHERE ts_end >= ?", (since,)).fetchone()
    out = dict(r)
    out['blocked'] = out['blocked'] or 0
    out['events'] = con.execute("SELECT COUNT(*) FROM events WHERE ts >= ? AND type='block'", (since,)).fetchone()[0]
    return out


BINDINGS = '/usr/local/etc/layer7security/bindings.conf'


def load_bindings():
    """mac, ip ('' = any), device, name per line, written by apply.php"""
    out = []
    try:
        with open(BINDINGS) as f:
            for line in f:
                line = line.rstrip('\r\n')
                if not line or line.startswith('#'):
                    continue
                parts = line.split('\t')
                if len(parts) >= 4:
                    out.append({'mac': parts[0].lower(), 'ip': '' if parts[1] == '-' else parts[1],
                                'device': '' if parts[2] == '-' else parts[2], 'name': parts[3]})
    except OSError:
        pass
    return out


def devices(con, period):
    """discovered devices annotated with their binding state"""
    binds = load_bindings()
    since = int(time.time()) - period
    out = rows(con, "SELECT ip, mac, iface, first_seen, last_seen, hits FROM devices WHERE last_seen >= ?"
                    " ORDER BY last_seen DESC LIMIT 500", (since,))
    for d in out:
        d['state'] = 'unbound'
        d['bound_name'] = ''
        for b in binds:
            same_ip = b['ip'] != '' and b['ip'] == d['ip']
            if same_ip and b['mac'] == d['mac']:
                d['state'], d['bound_name'] = 'bound', b['name']
                break
            if same_ip:
                d['state'], d['bound_name'] = 'spoof', b['name']
            elif b['ip'] == '' and b['mac'] == d['mac'] and d['state'] == 'unbound':
                d['state'], d['bound_name'] = 'mac-bound', b['name']
    return {'rows': out}


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'engine':
        try:
            with open(STATUS) as f:
                data = json.load(f)
            data['running'] = (time.time() - data.get('ts', 0)) < 30
        except (OSError, ValueError):
            data = {'running': False}
        print(json.dumps(data))
        return

    con = connect()
    if cmd == 'events':
        limit = to_int(sys.argv[2] if len(sys.argv) > 2 else 100, 100, 1, 500)
        print(json.dumps(rows(con, "SELECT ts, type, client, server, app, category, host, policy, detail"
                                   " FROM events ORDER BY id DESC LIMIT ?", (limit,)) if con else []))
        return

    if cmd == 'flows':
        limit = to_int(sys.argv[2], 25, 1, 500)
        offset = to_int(sys.argv[3], 0, 0)
        period = to_int(sys.argv[4], 86400)
        period = period if period in PERIODS else 86400
        only = sys.argv[5] if len(sys.argv) > 5 else 'all'
        phrase = sys.argv[6] if len(sys.argv) > 6 else '-'
        if con is None:
            print(json.dumps({'rows': [], 'total': 0}))
            return
        where = ['ts_end >= ?']
        args = [int(time.time()) - period]
        if only == 'blocked':
            where.append("action = 'block'")
        if phrase and phrase != '-' and re.match(r'^[A-Za-z0-9._:/ -]{1,64}$', phrase):
            like = '%' + phrase.replace('%', '').replace('_', r'\_') + '%'
            where.append("(client LIKE ? ESCAPE '\\' OR server LIKE ? ESCAPE '\\' OR app LIKE ? ESCAPE '\\'"
                         " OR category LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\' OR policy LIKE ? ESCAPE '\\')")
            args += [like] * 6
        cond = ' AND '.join(where)
        total = con.execute('SELECT COUNT(*) FROM flows WHERE ' + cond, args).fetchone()[0]
        data = rows(con, 'SELECT id, ts_start, ts_end, iface, l4, client, server, cport, sport, master, app,'
                         ' category, host, bytes_up, bytes_down, action, policy, country FROM flows WHERE ' + cond +
                    ' ORDER BY ts_end DESC LIMIT ? OFFSET ?', args + [limit, offset])
        print(json.dumps({'rows': data, 'total': total}))
        return

    period = to_int(sys.argv[2] if len(sys.argv) > 2 else 3600, 3600)
    period = period if period in PERIODS else 3600
    since = int(time.time()) - period
    if con is None:
        print(json.dumps({'error': 'no database yet'}))
        return
    if cmd == 'devices':
        out = devices(con, max(period, 3600))
    elif cmd == 'countries':
        out = {'rows': rows(con, "SELECT country, COUNT(*) AS flows, SUM(bytes_up+bytes_down) AS bytes"
                                 " FROM flows WHERE ts_end >= ? AND country IS NOT NULL AND country != ''"
                                 " GROUP BY country ORDER BY bytes DESC LIMIT 15", (since,))}
    elif cmd == 'summary':
        out = summary(con, since)
    elif cmd == 'apps':
        out = {'rows': rows(con, "SELECT app, category, COUNT(*) AS flows, SUM(bytes_up+bytes_down) AS bytes"
                                 " FROM flows WHERE ts_end >= ? AND app != 'Unknown'"
                                 " GROUP BY app, category ORDER BY bytes DESC LIMIT 15", (since,))}
    elif cmd == 'categories':
        out = {'rows': rows(con, "SELECT category, COUNT(*) AS flows, SUM(bytes_up+bytes_down) AS bytes"
                                 " FROM flows WHERE ts_end >= ? GROUP BY category ORDER BY bytes DESC LIMIT 12",
                            (since,))}
    elif cmd == 'clients':
        out = {'rows': rows(con, "SELECT client, COUNT(*) AS flows, SUM(bytes_up) AS up, SUM(bytes_down) AS down,"
                                 " SUM(action='block') AS blocked FROM flows WHERE ts_end >= ?"
                                 " GROUP BY client ORDER BY (up+down) DESC LIMIT 15", (since,))}
    elif cmd == 'timeline':
        bucket = max(60, period // 48)
        out = {'bucket': bucket, 'rows': rows(con, "SELECT (ts_end / ?) * ? AS t, SUM(bytes_up) AS up,"
                                                   " SUM(bytes_down) AS down, COUNT(*) AS flows FROM flows"
                                                   " WHERE ts_end >= ? GROUP BY t ORDER BY t",
                                              (bucket, bucket, since))}
    elif cmd == 'blocks':
        out = {'rows': rows(con, "SELECT policy, app, category, COUNT(*) AS hits FROM events"
                                 " WHERE ts >= ? AND type='block' GROUP BY policy, app, category"
                                 " ORDER BY hits DESC LIMIT 15", (since,))}
    else:
        out = {'error': 'unknown command'}
    print(json.dumps(out))


if __name__ == '__main__':
    main()
