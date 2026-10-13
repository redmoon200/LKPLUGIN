#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Live session console backend: the firewall's current connections (pf states)
# joined with what the engine knows about them (site name, application,
# country, policy decision). Prints JSON.
#
#   live.py sessions LIMIT PHRASE|- DIRECTIONS    DIRECTIONS: comma list of out,in,internal,firewall or "all"
#   live.py recent MINUTES                        blocks and detections of the last minutes
#   live.py events MODULE MINUTES LIMIT           MODULE: web, app, ai or all

import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import time

DB = '/var/db/layer7security/l7.db'
ENGINE_CONF = '/usr/local/etc/layer7security/engine.conf'
PFCTL = '/sbin/pfctl'
MAX_ROWS = 600

ARROW = re.compile(r'\s(<-|->)\s')
STATE_TAIL = re.compile(r'\s{2,}(\S+)\s*$')
AGE = re.compile(r'age (\d+):(\d+):(\d+), expires in (\d+):(\d+):(\d+), (\d+):(\d+) pkts, (\d+):(\d+) bytes')


def parse_endpoint(text):
    """'1.2.3.4:443', 'fe80::1[443]', 'ff02::1[134]', '10.0.0.1' -> (address, port or 0)"""
    text = text.strip()
    m = re.match(r'^(.*)\[(\d+)\]$', text)
    if m:
        return m.group(1), int(m.group(2))
    if text.count(':') == 1:
        host, port = text.split(':')
        if port.isdigit():
            return host, int(port)
    return text, 0


def parse_side(text):
    """'a:p (b:q)' -> ((a, p), (b, q) or None)"""
    m = re.match(r'^(.*?)\s*\((.*)\)\s*$', text.strip())
    if m:
        return parse_endpoint(m.group(1)), parse_endpoint(m.group(2))
    return parse_endpoint(text), None


def parse_states(text):
    """parse `pfctl -ss -v`; one dict per state that has an age/bytes line"""
    out = []
    cur = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            cur = None
            m = STATE_TAIL.search(line)
            a = ARROW.search(line)
            if not m or not a:
                continue
            head = line[:a.start()]
            parts = head.split(None, 2)
            if len(parts) < 3:
                continue
            iface, proto, left = parts
            right = line[a.end():m.start()]
            cur = {'iface': iface, 'proto': proto, 'arrow': a.group(1), 'left': parse_side(left),
                   'right': parse_side(right), 'state': m.group(1)}
        elif cur is not None:
            m = AGE.search(line)
            if m:
                g = [int(x) for x in m.groups()]
                cur.update(age=g[0] * 3600 + g[1] * 60 + g[2], expires=g[3] * 3600 + g[4] * 60 + g[5],
                           pkts_up=g[6], pkts_down=g[7], bytes_up=g[8], bytes_down=g[9])
                out.append(cur)
                cur = None
    return out


def to_session(st):
    """initiator/responder view of one parsed state; None for the duplicate translated half of a NAT pair"""
    (la, lport), lnat = st['left']
    (ra, rport), rnat = st['right']
    if st['arrow'] == '<-':
        # left answers, right started the connection; a translated left side shows the original destination
        server, sport = (lnat[0], lnat[1]) if lnat else (la, lport)
        proxied = (la, lport) if lnat else None
        client, cport = ra, rport
    else:
        if lnat:
            return None        # outbound half of a NAT pair, the inbound half carries the same numbers
        client, cport, server, sport = la, lport, ra, rport
        proxied = None
    return {'proto': st['proto'], 'client': client, 'cport': cport, 'server': server, 'sport': sport,
            'proxied': '%s:%d' % proxied if proxied else '', 'state': st['state'], 'iface': st['iface'],
            'age': st['age'], 'expires': st['expires'], 'up': st['bytes_up'], 'down': st['bytes_down'],
            'pup': st['pkts_up'], 'pdown': st['pkts_down']}


def local_networks():
    nets = []
    try:
        with open(ENGINE_CONF) as f:
            for line in f:
                if line.startswith('net='):
                    try:
                        nets.append(ipaddress.ip_network(line[4:].strip(), strict=False))
                    except ValueError:
                        pass
    except OSError:
        pass
    return nets


def firewall_addresses():
    out = set()
    try:
        res = subprocess.run(['/sbin/ifconfig', '-a'], capture_output=True, text=True, timeout=5)
        for m in re.finditer(r'^\s+inet6? (\S+?)(?:%\S+)?\s', res.stdout, re.M):
            out.add(m.group(1))
    except (OSError, subprocess.SubprocessError):
        pass
    return out


def is_local(addr, nets):
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if any(ip in n for n in nets):
        return True
    return not nets and (ip.is_private and not ip.is_loopback)


def classify(sess, nets, fw):
    cl, sv = sess['client'], sess['server']
    if cl in fw or cl in ('127.0.0.1', '::1'):
        return 'firewall'
    if sv in fw or sv in ('127.0.0.1', '::1'):
        return 'internal' if is_local(cl, nets) else 'in'
    if is_local(cl, nets):
        return 'internal' if is_local(sv, nets) else 'out'
    return 'in' if is_local(sv, nets) else 'other'


def connect():
    if not os.path.exists(DB):
        return None
    con = sqlite3.connect('file:%s?mode=ro' % DB, uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    return con


def enrich(rows, con):
    """site name, application, country and decision from the engine's flow records"""
    if con is None or not rows:
        return
    since = int(time.time()) - 900
    flows = {}
    for r in con.execute("SELECT client, server, cport, sport, host, app, category, country, action, policy, ai"
                         " FROM flows WHERE ts_end >= ? AND server != '' ORDER BY id", (since,)):
        flows[(r['client'], r['server'], r['cport'], r['sport'])] = r
    by_server = {}
    servers = sorted({r['server'] for r in rows})
    for i in range(0, len(servers), 400):
        chunk = servers[i:i + 400]
        q = ("SELECT server, host, app, category, country FROM flows WHERE server IN (%s) AND host != ''"
             " ORDER BY id" % ','.join('?' * len(chunk)))
        for r in con.execute(q, chunk):
            by_server[r['server']] = r
    for row in rows:
        f = flows.get((row['client'], row['server'], row['cport'], row['sport']))
        s = by_server.get(row['server'])
        row['host'] = (f['host'] if f and f['host'] else (s['host'] if s else '')) or ''
        row['app'] = (f['app'] if f else (s['app'] if s else '')) or ''
        row['category'] = (f['category'] if f else (s['category'] if s else '')) or ''
        row['country'] = (f['country'] if f and f['country'] else (s['country'] if s else '')) or ''
        row['action'] = (f['action'] if f else '') or ''
        row['policy'] = (f['policy'] if f else '') or ''
        row['ai'] = (f['ai'] if f else '') or ''


def sessions(limit, phrase, directions):
    try:
        res = subprocess.run([PFCTL, '-ss', '-v'], capture_output=True, text=True, timeout=15)
        states = parse_states(res.stdout)
    except (OSError, subprocess.SubprocessError):
        return {'rows': [], 'error': 'cannot read the state table'}
    nets = local_networks()
    fw = firewall_addresses()
    rows = []
    for st in states:
        s = to_session(st)
        if s is None or (s['proto'] in ('icmp', 'ipv6-icmp') and (s['age'] > 60 or not phrase or phrase == '-')):
            continue          # neighbour discovery and pings are noise unless somebody searches for them
        s['direction'] = classify(s, nets, fw)
        s['id'] = '%s|%s|%d|%s|%d' % (s['proto'], s['client'], s['cport'], s['server'], s['sport'])
        rows.append(s)
    counts = {}
    for r in rows:
        counts[r['direction']] = counts.get(r['direction'], 0) + 1
    total = len(rows)
    if directions != 'all':
        want = set(directions.split(','))
        rows = [r for r in rows if r['direction'] in want]
    rows.sort(key=lambda r: r['age'])
    rows = rows[:MAX_ROWS * 2]
    enrich(rows, connect())
    if phrase and phrase != '-':
        p = phrase.lower()
        rows = [r for r in rows if p in ' '.join(str(r.get(k, '')) for k in
                                                ('client', 'server', 'host', 'app', 'category', 'country', 'proto',
                                                 'cport', 'sport', 'policy', 'ai')).lower()]
    rows = rows[:limit]
    return {'rows': rows, 'total': total, 'counts': counts, 'ts': int(time.time())}


MODULE_FILTER = {
    'web': "policy LIKE 'Web Control%'",
    'ai': "(type LIKE 'ai-%' OR policy LIKE 'AI:%')",
    'app': "(type = 'block' AND policy NOT LIKE 'Web Control%' AND policy NOT LIKE 'AI:%')",
    'all': '1=1',
}


def events(module, minutes, limit):
    """engine events of one module (web control, application control, AI) in the last minutes"""
    con = connect()
    if con is None or module not in MODULE_FILTER:
        return {'rows': []}
    since = int(time.time()) - minutes * 60
    rows = [dict(r) for r in con.execute(
        "SELECT ts, type, client, server, app, category, host, policy, detail FROM events"
        " WHERE ts >= ? AND " + MODULE_FILTER[module] + " ORDER BY id DESC LIMIT ?", (since, limit))]
    return {'rows': rows}


def recent(minutes):
    con = connect()
    if con is None:
        return {'rows': []}
    since = int(time.time()) - minutes * 60
    rows = [dict(r) for r in con.execute(
        "SELECT ts, type, client, server, app, category, host, policy, detail FROM events"
        " WHERE ts >= ? AND type IN ('block', 'ai-block', 'spoof') ORDER BY id DESC LIMIT 50", (since,))]
    return {'rows': rows}


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'sessions'
    if cmd == 'events':
        module = sys.argv[2] if len(sys.argv) > 2 else 'all'
        minutes = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3].isdigit() else 1440
        limit = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4].isdigit() else 200
        print(json.dumps(events(module, max(1, min(minutes, 10080)), max(1, min(limit, 500)))))
        return
    if cmd == 'recent':
        minutes = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 10
        print(json.dumps(recent(max(1, min(minutes, 1440)))))
        return
    limit = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 200
    phrase = sys.argv[3] if len(sys.argv) > 3 else '-'
    if phrase != '-' and not re.match(r'^[A-Za-z0-9._:/ -]{1,64}$', phrase):
        phrase = '-'
    directions = sys.argv[4] if len(sys.argv) > 4 else 'all'
    if directions != 'all' and not re.match(r'^(out|in|internal|firewall|other)(,(out|in|internal|firewall|other))*$',
                                            directions):
        directions = 'all'
    print(json.dumps(sessions(max(1, min(limit, MAX_ROWS)), phrase, directions)))


if __name__ == '__main__':
    main()
