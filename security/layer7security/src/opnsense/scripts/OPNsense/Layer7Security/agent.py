#!/usr/local/bin/python3

# Copyright (c) 2026, redmoon200
# All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
#
# Monitoring agent: once a minute it reports the health of this firewall and a
# summary of what it blocked to the vendor's cloud server (L7 Cloud), where the
# vendor sees outages and alerts.
#
#   agent.py beat [--now]    gather and send one report (cron, every minute)
#   agent.py status          what the last report looked like (JSON)
#
# What is sent: CPU, memory, disk, load, pf states, uptime, engine and service state,
# gateway state (loss, delay), link state, whether the internet probes answered,
# counters of blocked traffic and the public addresses that were blocked on the way in
# (top 10), the number of clients that touched known-bad addresses (no client names or
# addresses), versions and the license state. No browsing history, no user names.
# It can be switched off in Layer 7 > License. Reports never stop the firewall:
# every failure is only recorded.
#
# An ISP outage cannot be reported while it lasts, so the agent keeps its own log of
# outages (gateway down, internet probes failing) and sends it with the next report.

import ipaddress
import json
import os
import random
import re
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cloudlib  # noqa: E402
import license_cloud as lc  # noqa: E402
import support  # noqa: E402
import update  # noqa: E402

STATE = os.path.join(cloudlib.BASE, 'agent.json')
ENGINE_DB = '/var/db/layer7security/l7.db'
ENGINE_STATUS = '/var/run/layer7security/status.json'
AV_DB = os.environ.get('L7_AV_DB', '/var/db/layer7security/av.db')
FILTER_LOG = '/var/log/filter/latest.log'
PROBES = (('1.1.1.1', 443), ('8.8.8.8', 443), ('9.9.9.9', 443))
MAX_WINDOW = 6 * 3600
MAX_LOG_READ = 4 * 1024 * 1024
MAX_OUTAGES = 50
THREAT = re.compile(r'botnet|malware|phish|c2|threat|drop|compromised|attacker|ransom|exploit', re.I)


def now():
    return int(time.time())


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


def sysctl(name):
    return run(['/sbin/sysctl', '-n', name], 5).strip()


def load_state():
    try:
        with open(STATE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(st):
    os.makedirs(cloudlib.BASE, exist_ok=True)
    tmp = STATE + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)      # holds the agent token
    with os.fdopen(fd, 'w') as f:
        json.dump(st, f)
    os.replace(tmp, STATE)


# ------------------------------------------------------------------ health

def cpu_percent(st):
    try:
        cur = [int(x) for x in sysctl('kern.cp_time').split()]
    except ValueError:
        return None
    prev = st.get('cp_time')
    st['cp_time'] = cur
    if not prev or len(prev) != len(cur) or len(cur) < 5:
        return None
    delta = [c - p for c, p in zip(cur, prev)]
    total = sum(delta)
    if total <= 0:
        return None
    return round(100.0 * (1 - delta[4] / total), 1)


def memory_percent():
    try:
        total = int(sysctl('hw.physmem'))
        page = int(sysctl('hw.pagesize'))
        free = 0
        for name in ('vm.stats.vm.v_free_count', 'vm.stats.vm.v_inactive_count', 'vm.stats.vm.v_laundry_count', 'vm.stats.vm.v_cache_count'):
            v = sysctl(name)
            free += int(v) if v.isdigit() else 0
        return round(100.0 * (1 - min(total, free * page) / total), 1), total
    except (ValueError, ZeroDivisionError):
        return None, 0


def disk_percent(path='/'):
    try:
        st = os.statvfs(path)
        used = (st.f_blocks - st.f_bfree) * st.f_frsize
        total = (st.f_blocks - st.f_bfree + st.f_bavail) * st.f_frsize
        return round(100.0 * used / total, 1) if total else None
    except OSError:
        return None


def pf_states():
    cur = limit = 0
    m = re.search(r'current entries\s+(\d+)', run(['/sbin/pfctl', '-si']))
    if m:
        cur = int(m.group(1))
    m = re.search(r'states\s+hard limit\s+(\d+)', run(['/sbin/pfctl', '-sm']))
    if m:
        limit = int(m.group(1))
    return cur, limit


def boot_time():
    m = re.search(r'sec = (\d+)', sysctl('kern.boottime'))
    return int(m.group(1)) if m else 0


def engine_state():
    out = {'running': False, 'ts': 0}
    try:
        with open(ENGINE_STATUS) as f:
            d = json.load(f)
        pid = int(d.get('pid', 0))
        os.kill(pid, 0)
        out.update({'running': now() - int(d.get('ts', 0)) < 45, 'ts': int(d.get('ts', 0)), 'version': str(d.get('version', ''))[:20],
                    'flows': int(d.get('flows_active', 0)), 'blocks_total': int(d.get('blocks', 0)),
                    'drops': sum(int(i.get('drop', 0)) for i in d.get('ifaces', []))})
    except (OSError, ValueError, TypeError):
        pass
    return out


def process_running(pattern):
    return bool(run(['/bin/pgrep', '-f', pattern], 5).strip())


def links():
    """interface -> active / no carrier, skipping loopback and virtual interfaces"""
    out, name = {}, None
    for line in run(['/sbin/ifconfig', '-a'], 8).splitlines():
        m = re.match(r'^([a-z]+[0-9.]*[0-9]*):', line)
        if m:
            name = m.group(1)
            continue
        if name and re.match(r'^(vtnet|em|igb|igc|ix|re|bge|ue|vlan|lagg|mvneta|axgbe|ixl|cc)', name):
            s = re.match(r'^\s+status: (.+)$', line)
            if s:
                out[name] = 'active' if s.group(1).strip() == 'active' else 'down'
    return out


def to_num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def gateways():
    try:
        rows = json.loads(run(['/usr/local/sbin/configctl', 'interface', 'gateways', 'status'], 20) or '[]')
    except ValueError:
        return []
    out = []
    for g in rows if isinstance(rows, list) else []:
        if not isinstance(g, dict):
            continue
        out.append({'name': str(g.get('name', ''))[:32], 'address': str(g.get('address', ''))[:64], 'status': str(g.get('status', ''))[:12],
                    'loss': to_num(g.get('loss')), 'delay': to_num(g.get('delay')), 'stddev': to_num(g.get('stddev'))})
    return out[:12]


def probe_internet():
    ok = 0
    for host, port in PROBES:
        try:
            with socket.create_connection((host, port), timeout=3):
                ok += 1
        except OSError:
            pass
    return ok


# ------------------------------------------------------------------ outages kept locally

def track_outages(st, gws, internet_ok, ts):
    """open and close outage records; they are sent until the server confirms them"""
    outs = st.setdefault('outages', [])
    seen_down = {'gw:' + g['name'] for g in gws if g['status'] in ('down', 'force_down')}
    fail_count = st.get('probe_fail', 0)
    fail_count = fail_count + 1 if internet_ok == 0 else 0
    st['probe_fail'] = fail_count
    if fail_count >= 2:
        seen_down.add('internet')
    open_by_kind = {o['kind']: o for o in outs if not o.get('end')}
    for kind in seen_down:
        if kind not in open_by_kind:
            # an internet outage started when the first probe failed, one minute before it was confirmed
            start = ts - 60 if kind == 'internet' else ts
            outs.append({'kind': kind, 'start': start, 'end': 0})
    for kind, o in open_by_kind.items():
        if kind not in seen_down:
            o['end'] = ts
    st['outages'] = outs[-MAX_OUTAGES:]


# ------------------------------------------------------------------ security summary

def public_v4(addr):
    try:
        ip = ipaddress.ip_address(addr)
        return ip.version == 4 and ip.is_global and not ip.is_multicast and not ip.is_reserved
    except ValueError:
        return False


def read_filter_log(st):
    """blocked inbound packets since the last report: totals and the busiest public sources"""
    out = {'in_blocks': 0, 'public_blocks': 0, 'top': [], 'scanners': 0}
    try:
        real = os.path.realpath(FILTER_LOG)
        info = os.stat(real)
    except OSError:
        return out
    cur = st.get('filter') or {}
    off = cur.get('off', 0) if cur.get('ino') == info.st_ino and cur.get('off', 0) <= info.st_size else 0
    if cur.get('ino') is None:
        off = max(0, info.st_size - 1)                # first run: start at the end
    if info.st_size - off > MAX_LOG_READ:
        off = info.st_size - MAX_LOG_READ
    per = {}
    try:
        with open(real, 'rb') as f:
            f.seek(off)
            data = f.read(MAX_LOG_READ)
    except OSError:
        return out
    end = data.rfind(b'\n') + 1                       # never consume a half-written line
    st['filter'] = {'ino': info.st_ino, 'off': off + end}
    for raw in data[:end].decode('utf-8', 'replace').splitlines():
        if 'filterlog' not in raw:
            continue
        csv = raw.split('] ', 1)[-1].split(',')
        if len(csv) < 20 or csv[6] != 'block' or csv[7] != 'in' or csv[8] != '4':
            continue
        out['in_blocks'] += 1
        src = csv[18]
        if not public_v4(src):
            continue
        out['public_blocks'] += 1
        rec = per.setdefault(src, {'ip': src, 'hits': 0, 'ports': set(), 'iface': csv[4][:16], 'proto': csv[16][:8]})
        rec['hits'] += 1
        if csv[16] in ('tcp', 'udp') and len(csv) > 21 and len(rec['ports']) < 500:
            rec['ports'].add(csv[21])
    top = sorted(per.values(), key=lambda r: -r['hits'])[:10]
    out['top'] = [{'ip': r['ip'], 'hits': r['hits'], 'ports': len(r['ports']), 'iface': r['iface'], 'proto': r['proto']} for r in top]
    out['scanners'] = sum(1 for r in per.values() if len(r['ports']) >= 10)
    return out


def engine_events(since):
    out = {'blocks': 0, 'threat_hits': 0, 'threat_clients': 0, 'threat_top': [], 'mac_spoofs': 0, 'new_devices': 0}
    if not os.path.exists(ENGINE_DB):
        return out
    try:
        con = sqlite3.connect('file:%s?mode=ro' % ENGINE_DB, uri=True, timeout=3)
        rows = con.execute('SELECT type, category, host, server, client FROM events WHERE ts > ? LIMIT 20000', (since,)).fetchall()
        con.close()
    except sqlite3.Error:
        return out
    clients, top = set(), {}
    for typ, cat, host, srv, client in rows:
        if typ == 'block':
            out['blocks'] += 1
            if cat and THREAT.search(cat):
                out['threat_hits'] += 1
                clients.add(client)
                key = (str(host or srv or '')[:80], str(cat)[:30])
                top[key] = top.get(key, 0) + 1
        elif typ == 'mac-spoof':
            out['mac_spoofs'] += 1
        elif typ == 'device-new':
            out['new_devices'] += 1
    out['threat_clients'] = len(clients)
    out['threat_top'] = [{'target': k[0], 'category': k[1], 'hits': v} for k, v in sorted(top.items(), key=lambda kv: -kv[1])[:5]]
    return out


def av_detections(since):
    if not os.path.exists(AV_DB):
        return 0
    try:
        con = sqlite3.connect('file:%s?mode=ro' % AV_DB, uri=True, timeout=3)
        n = con.execute('SELECT COUNT(*) FROM av_events WHERE ts > ?', (since,)).fetchone()[0]
        con.close()
        return int(n)
    except sqlite3.Error:
        return 0


# ------------------------------------------------------------------ report

def opnsense_version():
    m = re.search(r'OPNsense\s+(\S+)', run(['/usr/local/sbin/opnsense-version'], 8))
    return m.group(1)[:24] if m else ''


def gather(st, cfg, ts):
    since = st.get('last_ok') or ts - 60
    since = max(since, ts - MAX_WINDOW)
    mem, mem_total = memory_percent()
    states, states_limit = pf_states()
    gws = gateways()
    internet = probe_internet()
    track_outages(st, gws, internet, ts)
    load = os.getloadavg()
    general = cfg.get('general', {})
    health = {'cpu': cpu_percent(st), 'mem': mem, 'mem_total': mem_total, 'disk': disk_percent('/'), 'load1': round(load[0], 2),
              'states': states, 'states_limit': states_limit, 'boot': boot_time(), 'ncpu': to_num(sysctl('hw.ncpu')),
              'engine': engine_state(), 'engine_expected': general.get('enabled') == '1',
              'unbound': process_running('/unbound -c'), 'squid': process_running('squid'),
              'links': links()}
    sec = read_filter_log(st)
    sec.update(engine_events(since))
    sec['av_detections'] = av_detections(since)
    sec['window'] = ts - since
    lic = lc.read_state()
    return {'install_id': lc.install_id(), 'key': lc.current_key(), 'ts': ts, 'seq': st.get('seq', 0) + 1,
            'hostname': os.uname().nodename[:64], 'version': lc.plugin_version(), 'opnsense': opnsense_version(),
            'health': health, 'gateways': gws, 'internet': {'ok': internet, 'of': len(PROBES)}, 'security': sec,
            'license': {'state': lic.get('server_state', ''), 'lastCheckin': lic.get('ts', 0)}, 'support': {'level': support.local_level()}, 'updates': update.summary(),
            'feedsUpdated': lc.last_feed_update(), 'outages': [o for o in st.get('outages', [])][-MAX_OUTAGES:]}


def post(url, payload, token, timeout=20):
    headers = {'Content-Type': 'application/json', 'User-Agent': 'os-layer7security'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read(65536).decode('utf-8', 'replace'))
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read(65536).decode('utf-8', 'replace'))
        except ValueError:
            return {'ok': False, 'error': 'server answered HTTP %d' % exc.code}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {'ok': False, 'error': 'cannot reach the server (%s)' % str(getattr(exc, 'reason', exc))[:80]}


def beat(immediate=False):
    cfg = cloudlib.settings()
    st = load_state()
    if cfg['general'].get('monitoring') == '0':
        st.update({'enabled': False})
        save_state(st)
        return {'ok': False, 'skipped': 'Monitoring is switched off on this firewall.'}
    st['enabled'] = True
    root = lc.server_root(cfg)
    if not root:
        st.update({'last_try': now(), 'error': 'No cloud server address is set.'})
        save_state(st)
        return {'ok': False, 'error': st['error']}
    if not immediate:
        time.sleep(random.uniform(0, 12))            # many firewalls must not report in the same second
    ts = now()
    payload = gather(st, cfg, ts)
    res = post(root + '/api/v1/beat', payload, st.get('token', ''))
    st['last_try'] = ts
    if res.get('ok'):
        st['seq'] = payload['seq']
        st['last_ok'] = ts
        st['error'] = ''
        if res.get('token'):
            st['token'] = str(res['token'])[:80]
        got = {int(x) for x in res.get('got_outages', []) if isinstance(x, int)}
        st['outages'] = [o for o in st.get('outages', []) if not (o.get('end') and o.get('start') in got)]
        st['server_time'] = res.get('server_time', 0)
        st['alerts_open'] = int(res.get('open_alerts', 0) or 0)
    else:
        st['error'] = str(res.get('error', 'the server did not accept the report'))[:160]
    save_state(st)
    if res.get('ok') and res.get('poll') and support.local_level() != 'off' and st.get('token'):
        support_session(root, payload['install_id'], st['token'])
    return {'ok': bool(res.get('ok')), 'error': st['error'], 'seq': payload['seq']}


def support_session(root, install_id, token):
    """the vendor has the support page open or a command is waiting: poll quickly for the rest of this minute"""
    try:
        import fcntl
        lock = open(os.path.join(cloudlib.BASE, 'support.lock'), 'w')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)         # a second run must not poll at the same time
    except (ImportError, OSError):
        return
    try:
        support.poll_loop(post, root, install_id, token, 38)
    finally:
        lock.close()


def status():
    st = load_state()
    cfg = cloudlib.settings()
    return {'enabled': cfg['general'].get('monitoring') != '0', 'lastOk': st.get('last_ok', 0), 'lastTry': st.get('last_try', 0),
            'error': st.get('error', ''), 'enrolled': bool(st.get('token')), 'pendingOutages': len(st.get('outages', [])),
            'alertsOpen': st.get('alerts_open', 0)}


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'status'
    if cmd == 'beat':
        print(json.dumps(beat('--now' in sys.argv)))
    else:
        print(json.dumps(status()))


if __name__ == '__main__':
    main()
