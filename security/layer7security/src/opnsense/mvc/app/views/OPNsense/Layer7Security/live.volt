<div class="l7">
    {{ partial('OPNsense/Layer7Security/partials/header', [
        'title': lang._('Live Sessions'),
        'subtitle': lang._('Everything that is connected through the firewall right now. Click Block or Allow next to a connection to act on it at once.'),
        'icon': 'eye',
        'accent': 'con',
        'apply': false
    ]) }}

    <div class="l7-tiles" id="live-tiles"></div>

    <ul class="nav nav-tabs" role="tablist">
        <li class="active"><a data-toggle="tab" href="#tab-conn">{{ lang._('Connections') }}</a></li>
        <li><a data-toggle="tab" href="#tab-devices">{{ lang._('By device') }}</a></li>
        <li><a data-toggle="tab" href="#tab-sites">{{ lang._('By website') }}</a></li>
        <li><a data-toggle="tab" href="#tab-blocked">{{ lang._('Blocked just now') }}</a></li>
        <li><a data-toggle="tab" href="#tab-history">{{ lang._('History') }}</a></li>
    </ul>

    <div class="tab-content">
        <div id="tab-conn" class="tab-pane fade in active">
            <div class="l7-toolbar">
                <input type="text" id="live-q" class="form-control grow" placeholder="{{ lang._('Search by device, website, address, port, application or country') }}" maxlength="64"/>
                <span class="l7-chip on" data-dir="out" title="{{ lang._('Devices on your network talking to the internet') }}">{{ lang._('Outgoing') }}</span>
                <span class="l7-chip on" data-dir="in" title="{{ lang._('Connections coming in from the internet') }}">{{ lang._('Incoming') }}</span>
                <span class="l7-chip on" data-dir="internal" title="{{ lang._('Between your networks, and to the firewall itself (DNS, web interface)') }}">{{ lang._('Internal') }}</span>
                <span class="l7-chip" data-dir="firewall" title="{{ lang._('Connections the firewall itself makes') }}">{{ lang._('Firewall') }}</span>
                <select id="live-every" class="form-control" style="width:auto">
                    <option value="2000">{{ lang._('Refresh every 2 s') }}</option>
                    <option value="3000" selected="selected">{{ lang._('Refresh every 3 s') }}</option>
                    <option value="5000">{{ lang._('Refresh every 5 s') }}</option>
                    <option value="10000">{{ lang._('Refresh every 10 s') }}</option>
                </select>
                <button class="btn btn-default" id="live-pause" type="button"><i class="fa fa-pause"></i> <span>{{ lang._('Pause') }}</span></button>
            </div>
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-conn">
                    <thead>
                        <tr>
                            <th></th>
                            <th class="sortable" data-sort="client">{{ lang._('Device') }}</th>
                            <th class="sortable" data-sort="dest">{{ lang._('Destination') }}</th>
                            <th class="sortable" data-sort="sport">{{ lang._('Port') }}</th>
                            <th class="sortable" data-sort="app">{{ lang._('Application') }}</th>
                            <th class="sortable" data-sort="country">{{ lang._('Country') }}</th>
                            <th class="sortable num" data-sort="rdown">{{ lang._('Download') }}</th>
                            <th class="sortable num" data-sort="rup">{{ lang._('Upload') }}</th>
                            <th class="sortable num" data-sort="total">{{ lang._('Total') }}</th>
                            <th class="sortable num" data-sort="age">{{ lang._('Age') }}</th>
                            <th>{{ lang._('Decision') }}</th>
                            <th>{{ lang._('Action') }}</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
            <div class="l7-muted" id="live-foot" style="margin-top:8px;font-size:12px"></div>
        </div>

        <div id="tab-devices" class="tab-pane fade">
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-devices">
                    <thead>
                        <tr>
                            <th>{{ lang._('Device') }}</th>
                            <th class="num">{{ lang._('Connections') }}</th>
                            <th class="num">{{ lang._('Websites') }}</th>
                            <th class="num">{{ lang._('Download') }}</th>
                            <th class="num">{{ lang._('Upload') }}</th>
                            <th class="num">{{ lang._('Total') }}</th>
                            <th>{{ lang._('Busiest website') }}</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>

        <div id="tab-sites" class="tab-pane fade">
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-sites">
                    <thead>
                        <tr>
                            <th>{{ lang._('Website or address') }}</th>
                            <th>{{ lang._('Application') }}</th>
                            <th>{{ lang._('Country') }}</th>
                            <th class="num">{{ lang._('Devices') }}</th>
                            <th class="num">{{ lang._('Connections') }}</th>
                            <th class="num">{{ lang._('Download') }}</th>
                            <th class="num">{{ lang._('Total') }}</th>
                            <th>{{ lang._('Action') }}</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>

        <div id="tab-blocked" class="tab-pane fade">
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-blocked">
                    <thead>
                        <tr>
                            <th>{{ lang._('Time') }}</th>
                            <th>{{ lang._('Device') }}</th>
                            <th>{{ lang._('Website or address') }}</th>
                            <th>{{ lang._('Application') }}</th>
                            <th>{{ lang._('Rule') }}</th>
                            <th>{{ lang._('Action') }}</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>

        <div id="tab-history" class="tab-pane fade">
            <div class="l7-toolbar">
                <select id="flow-period" class="form-control" style="width:auto">
                    <option value="300">{{ lang._('Last 5 minutes') }}</option>
                    <option value="3600">{{ lang._('Last hour') }}</option>
                    <option value="21600">{{ lang._('Last 6 hours') }}</option>
                    <option value="86400" selected="selected">{{ lang._('Last 24 hours') }}</option>
                    <option value="604800">{{ lang._('Last 7 days') }}</option>
                </select>
                <label style="margin:0"><input type="checkbox" id="flow-blocked"> {{ lang._('Blocked only') }}</label>
            </div>
            <table id="grid-flows" class="table table-condensed table-hover table-striped" data-store-selection="false">
                <thead>
                    <tr>
                        <th data-column-id="ts_end" data-formatter="time" data-width="10em">{{ lang._('Last seen') }}</th>
                        <th data-column-id="client" data-type="string">{{ lang._('Device') }}</th>
                        <th data-column-id="host" data-formatter="site">{{ lang._('Website or address') }}</th>
                        <th data-column-id="country" data-type="string" data-width="5em">{{ lang._('Country') }}</th>
                        <th data-column-id="sport" data-type="numeric" data-width="5em">{{ lang._('Port') }}</th>
                        <th data-column-id="app" data-type="string">{{ lang._('Application') }}</th>
                        <th data-column-id="bytes_down" data-formatter="bytes" data-width="7em">{{ lang._('Down') }}</th>
                        <th data-column-id="bytes_up" data-formatter="bytes" data-width="7em">{{ lang._('Up') }}</th>
                        <th data-column-id="action" data-formatter="action" data-width="6em">{{ lang._('Decision') }}</th>
                        <th data-column-id="policy" data-type="string">{{ lang._('Rule') }}</th>
                        <th data-column-id="cmds" data-formatter="cmds" data-sortable="false" data-width="9em">{{ lang._('Action') }}</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </div>
</div>

<script>
$(document).ready(function () {
    var E = L7.esc;
    var S = {rows: [], prev: {}, paused: false, dirs: {out: true, 'in': true, internal: true, firewall: false},
             q: '', sort: {key: 'age', dir: 1}, every: 3000, timer: null, view: [], total: 0, blocked10: 0, lastTs: 0,
             recent: [], busy: false};

    L7.engineStatus('#l7-engine-pill');
    $('#l7-module-pill').replaceWith($(L7.pill("{{ lang._('Live') }}", 'ok')).attr('id', 'l7-module-pill'));
    L7.rememberTabs('live');

    /* ---------------- polling ---------------- */
    function dirList() {
        var d = [];
        $.each(S.dirs, function (k, v) { if (v) { d.push(k); } });
        return d.length ? d.join(',') : 'out';
    }

    function poll() {
        if (S.paused || S.busy) { return; }
        S.busy = true;
        L7.get('/api/layer7security/live/sessions', {limit: 500, q: S.q, dir: dirList()}).done(function (data) {
            S.busy = false;
            if (data && data.rows) { ingest(data); }
        }).fail(function () { S.busy = false; });
    }

    function schedule() {
        clearInterval(S.timer);
        S.timer = setInterval(poll, S.every);
    }

    function ingest(data) {
        var ts = data.ts || Math.floor(Date.now() / 1000);
        var dt = Math.max(1, ts - (S.lastTs || ts - 3));
        var next = {};
        data.rows.forEach(function (r) {
            var p = S.prev[r.id];
            r.dest = r.host || r.server;
            r.total = r.up + r.down;
            r.rdown = p ? Math.max(0, (r.down - p.down) / dt) : 0;
            r.rup = p ? Math.max(0, (r.up - p.up) / dt) : 0;
            r.fresh = !p && S.lastTs > 0;
            next[r.id] = {up: r.up, down: r.down};
        });
        S.prev = next;
        S.lastTs = ts;
        S.rows = data.rows;
        S.total = data.total || data.rows.length;
        render();
    }

    /* ---------------- rendering ---------------- */
    function cmp(a, b) {
        var k = S.sort.key, x = a[k], y = b[k];
        if (typeof x === 'string' || typeof y === 'string') {
            x = String(x || '').toLowerCase(); y = String(y || '').toLowerCase();
            return x < y ? -S.sort.dir : (x > y ? S.sort.dir : 0);
        }
        return ((x || 0) - (y || 0)) * S.sort.dir;
    }

    function dirIcon(d) {
        var map = {out: ['arrow-up', 'Outgoing'], 'in': ['arrow-down', 'Incoming'], internal: ['exchange', 'Internal'],
                   firewall: ['shield', 'Firewall'], other: ['question', 'Other']};
        var m = map[d] || map.other;
        return '<span class="l7-dir ' + E(d) + '" title="' + E(m[1]) + '"><i class="fa fa-' + m[0] + '"></i></span>';
    }

    function decision(r) {
        if (r.action === 'block') { return L7.tag('{{ lang._('Blocked') }}', 'block'); }
        if (r.action === 'allow') { return L7.tag('{{ lang._('Allowed') }}', 'allow'); }
        if (r.action === 'monitor') { return L7.tag('{{ lang._('Watched') }}', 'monitor'); }
        return '<span class="l7-muted">-</span>';
    }

    function actionButtons(r, idx) {
        var h = '<span class="l7-act">';
        h += '<button class="btn btn-xs btn-danger act-block" data-i="' + idx + '" title="{{ lang._('Block this website or address') }}"><i class="fa fa-ban"></i> {{ lang._('Block') }}</button> ';
        h += '<button class="btn btn-xs btn-success act-allow" data-i="' + idx + '" title="{{ lang._('Always allow this website or address') }}"><i class="fa fa-check"></i> {{ lang._('Allow') }}</button> ';
        h += '<button class="btn btn-xs btn-default act-info" data-i="' + idx + '" title="{{ lang._('Session details') }}"><i class="fa fa-info"></i></button>';
        return h + '</span>';
    }

    function render() {
        var rows = S.rows.slice().sort(cmp);
        S.view = rows;
        var down = 0, up = 0, clients = {}, remotes = {}, blocked = 0;
        S.rows.forEach(function (r) {
            down += r.rdown; up += r.rup; clients[r.client] = 1; remotes[r.server] = 1;
            if (r.action === 'block') { blocked++; }
        });
        $('#live-tiles').html(
            L7.tile(L7.num(S.total), '{{ lang._('Connections now') }}', S.rows.length < S.total ? '{{ lang._('showing') }} ' + S.rows.length : '') +
            L7.tile(L7.num(Object.keys(clients).length), '{{ lang._('Devices') }}') +
            L7.tile(L7.num(Object.keys(remotes).length), '{{ lang._('Remote addresses') }}') +
            L7.tile(L7.rate(down), '{{ lang._('Download') }}') +
            L7.tile(L7.rate(up), '{{ lang._('Upload') }}') +
            L7.tile(L7.num(blocked), '{{ lang._('Blocked in view') }}', '', blocked ? 'bad' : '')
        );
        var body = rows.slice(0, 300).map(function (r, i) {
            var cls = (r.action === 'block' ? 'blocked ' : '') + (r.fresh ? 'fresh' : '');
            return '<tr class="' + cls + '" data-i="' + i + '">' +
                '<td>' + dirIcon(r.direction) + '</td>' +
                '<td class="mono">' + E(r.client) + '<span class="l7-muted">:' + E(r.cport || '') + '</span></td>' +
                '<td class="trunc" title="' + E(r.server) + '">' + (r.host ? E(r.host) + ' <span class="l7-muted mono">' + E(r.server) + '</span>' : '<span class="mono">' + E(r.server) + '</span>') + '</td>' +
                '<td>' + E(r.sport || '') + '<span class="l7-muted">/' + E(r.proto) + '</span></td>' +
                '<td>' + E(r.app) + (r.category ? ' <span class="l7-muted">' + E(r.category) + '</span>' : '') + '</td>' +
                '<td>' + E(L7.flag(r.country)) + ' ' + E(r.country) + '</td>' +
                '<td class="num">' + (r.rdown > 0 ? L7.rate(r.rdown) : '<span class="l7-muted">0</span>') + '</td>' +
                '<td class="num">' + (r.rup > 0 ? L7.rate(r.rup) : '<span class="l7-muted">0</span>') + '</td>' +
                '<td class="num">' + L7.bytes(r.total) + '</td>' +
                '<td class="num">' + L7.dur(r.age) + '</td>' +
                '<td>' + decision(r) + '</td>' +
                '<td>' + actionButtons(r, i) + '</td></tr>';
        }).join('');
        $('#tbl-conn tbody').html(body || '<tr><td colspan="12">' + L7.empty('plug', '{{ lang._('No connections match.') }}') + '</td></tr>');
        $('#live-foot').text(S.paused ? '{{ lang._('Paused. Click Resume to continue.') }}' : '{{ lang._('Updated') }} ' + new Date().toLocaleTimeString());
        renderDevices();
        renderSites();
    }

    function renderDevices() {
        var by = {};
        S.rows.forEach(function (r) {
            var d = by[r.client] || (by[r.client] = {client: r.client, n: 0, down: 0, up: 0, total: 0, sites: {}});
            d.n++; d.down += r.rdown; d.up += r.rup; d.total += r.total;
            var s = r.host || r.server;
            d.sites[s] = (d.sites[s] || 0) + r.total;
        });
        var list = Object.keys(by).map(function (k) {
            var d = by[k];
            var best = Object.keys(d.sites).sort(function (a, b) { return d.sites[b] - d.sites[a]; })[0] || '';
            d.top = best; d.nsites = Object.keys(d.sites).length;
            return d;
        }).sort(function (a, b) { return b.total - a.total; });
        $('#tbl-devices tbody').html(list.map(function (d) {
            return '<tr><td class="mono">' + E(d.client) + '</td><td class="num">' + d.n + '</td><td class="num">' + d.nsites + '</td>' +
                '<td class="num">' + L7.rate(d.down) + '</td><td class="num">' + L7.rate(d.up) + '</td><td class="num">' + L7.bytes(d.total) + '</td>' +
                '<td class="trunc">' + E(d.top) + '</td>' +
                '<td><button class="btn btn-xs btn-default act-filter" data-q="' + E(d.client) + '"><i class="fa fa-search"></i> {{ lang._('Show connections') }}</button></td></tr>';
        }).join('') || '<tr><td colspan="8">' + L7.empty('desktop', '{{ lang._('No devices.') }}') + '</td></tr>');
    }

    function renderSites() {
        var by = {};
        S.rows.forEach(function (r, idx) {
            var key = r.host || r.server;
            var d = by[key] || (by[key] = {key: key, host: r.host, server: r.server, app: r.app, country: r.country, n: 0, devs: {}, down: 0, total: 0, row: r});
            d.n++; d.devs[r.client] = 1; d.down += r.rdown; d.total += r.total;
        });
        S.sites = Object.keys(by).map(function (k) { return by[k]; }).sort(function (a, b) { return b.total - a.total; }).slice(0, 200);
        $('#tbl-sites tbody').html(S.sites.map(function (d, i) {
            return '<tr><td class="trunc">' + E(d.key) + '</td><td>' + E(d.app) + '</td><td>' + E(L7.flag(d.country)) + ' ' + E(d.country) + '</td>' +
                '<td class="num">' + Object.keys(d.devs).length + '</td><td class="num">' + d.n + '</td><td class="num">' + L7.rate(d.down) + '</td>' +
                '<td class="num">' + L7.bytes(d.total) + '</td>' +
                '<td><span class="l7-act"><button class="btn btn-xs btn-danger site-block" data-i="' + i + '"><i class="fa fa-ban"></i> {{ lang._('Block') }}</button> ' +
                '<button class="btn btn-xs btn-success site-allow" data-i="' + i + '"><i class="fa fa-check"></i> {{ lang._('Allow') }}</button></span></td></tr>';
        }).join('') || '<tr><td colspan="8">' + L7.empty('globe', '{{ lang._('No websites.') }}') + '</td></tr>');
    }

    /* ---------------- recently blocked ---------------- */
    function loadRecent() {
        L7.get('/api/layer7security/live/recent', {minutes: 10}).done(function (d) {
            S.recent = (d && d.rows) || [];
            $('#tbl-blocked tbody').html(S.recent.map(function (r, i) {
                return '<tr><td>' + E(L7.ago(r.ts)) + '</td><td class="mono">' + E(r.client) + '</td><td class="trunc">' + E(r.host || r.server) + '</td>' +
                    '<td>' + E(r.app) + '</td><td>' + E(r.policy) + '</td>' +
                    '<td><button class="btn btn-xs btn-success rec-allow" data-i="' + i + '"><i class="fa fa-check"></i> {{ lang._('Allow') }}</button></td></tr>';
            }).join('') || '<tr><td colspan="6">' + L7.empty('check-circle', '{{ lang._('Nothing was blocked in the last 10 minutes.') }}') + '</td></tr>');
        });
    }

    /* ---------------- quick action dialog ---------------- */
    function targetsFor(host, ip) {
        var t = [];
        if (host) {
            t.push({kind: 'domain', value: host, label: '{{ lang._('This website only') }}', sub: host + ' {{ lang._('and everything below it') }}'});
            var reg = L7.registrable(host);
            if (reg && reg !== host) {
                t.push({kind: 'domain', value: '*.' + reg, label: '{{ lang._('The whole site') }}', sub: '*.' + reg + ' {{ lang._('(every sub-domain, e.g. cdn.') }}' + reg + ')'});
            }
        }
        if (ip) { t.push({kind: 'ip', value: ip, label: '{{ lang._('Only the IP address') }}', sub: ip + ' {{ lang._('(all traffic to this address)') }}'}); }
        return t;
    }

    function isPrivate(ip) {
        ip = String(ip || '').toLowerCase();
        if (/^(10\.|127\.|192\.168\.|169\.254\.)/.test(ip) || /^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip)) { return true; }
        return /^(fe[89ab][0-9a-f]:|f[cd][0-9a-f]{2}:|::1$)/.test(ip);
    }

    function quick(action, ctx) {
        var targets = targetsFor(ctx.host, ctx.ip);
        if (!targets.length) { L7.toast('{{ lang._('Nothing to act on.') }}', 'warn'); return; }
        var verb = action === 'block' ? '{{ lang._('Block') }}' : '{{ lang._('Allow') }}';
        var opts = targets.map(function (t, i) {
            return '<div class="radio" style="margin:4px 0"><label><input type="radio" name="qa-what" value="' + i + '"' + (i === 0 ? ' checked' : '') + '> <strong>' +
                E(t.label) + '</strong><br><span class="l7-muted mono">' + E(t.sub) + '</span></label></div>';
        }).join('');
        var who = '<select id="qa-who" class="form-control"><option value="">{{ lang._('Everyone') }}</option>' +
            (ctx.client && action === 'block' ? '<option value="' + E(ctx.client) + '">{{ lang._('Only this device') }} (' + E(ctx.client) + ')</option>' : '') + '</select>';
        var howlong = '<select id="qa-long" class="form-control"><option value="0">{{ lang._('Always (until I remove it)') }}</option>' +
            '<option value="60">{{ lang._('1 hour') }}</option><option value="480">{{ lang._('8 hours') }}</option><option value="1440">{{ lang._('1 day') }}</option>' +
            '<option value="10080">{{ lang._('7 days') }}</option><option value="43200">{{ lang._('30 days') }}</option></select>';
        var internal = (!ctx.host && isPrivate(ctx.ip)) ? '<div class="l7-hint warn">{{ lang._('This is an address on your own network. Blocking it stops devices from reaching it.') }}</div>' : '';
        var msg = '<div class="l7">' + internal +
            '<p>' + (action === 'block' ? '{{ lang._('The connection will be closed and nobody covered by this rule can reach it again.') }}' :
                     '{{ lang._('This overrides blocking rules, so the website or address can always be reached.') }}') + '</p>' +
            '<div class="form-group"><label>{{ lang._('What') }}</label>' + opts + '</div>' +
            (action === 'block' ? '<div class="form-group"><label>{{ lang._('For') }}</label>' + who + '</div>' : '') +
            '<div class="form-group"><label>{{ lang._('How long') }}</label>' + howlong + '</div>' +
            '<div class="form-group"><label>{{ lang._('Note (optional)') }}</label><input id="qa-note" class="form-control" maxlength="100" placeholder="{{ lang._('Why? For example: ticket 1234') }}"></div></div>';
        BootstrapDialog.show({
            type: action === 'block' ? BootstrapDialog.TYPE_DANGER : BootstrapDialog.TYPE_SUCCESS,
            title: verb + ' ' + (ctx.host || ctx.ip) + '?',
            message: msg,
            buttons: [
                {label: '{{ lang._('Cancel') }}', action: function (d) { d.close(); }},
                {id: 'qa-yes', label: verb, cssClass: action === 'block' ? 'btn-danger' : 'btn-success', action: function (d) {
                    var t = targets[parseInt($('input[name=qa-what]:checked').val() || '0', 10)];
                    var body = {kind: t.kind, value: t.value, action: action, minutes: parseInt($('#qa-long').val(), 10),
                                source: action === 'block' ? $('#qa-who').val() : '', note: $('#qa-note').val(), origin: 'live'};
                    var $yes = d.getButton('qa-yes');
                    $yes.spin();
                    $yes.disable();
                    L7.post('/api/layer7security/webcontrol/quick', body).done(function (res) {
                        d.close();
                        if (res && res.result === 'saved' && res.applied !== false) {
                            L7.toast(verb + ': ' + t.value + (body.minutes ? ' ({{ lang._('temporary') }})' : '') + '. {{ lang._('Active now.') }}');
                        } else {
                            L7.toast((res && res.message) || '{{ lang._('The rule was saved but could not be applied.') }}', 'bad');
                        }
                        setTimeout(function () { poll(); loadRecent(); }, 1500);
                    }).fail(function () { d.close(); L7.toast('{{ lang._('The request failed.') }}', 'bad'); });
                }}
            ]
        });
    }

    function ctxOfRow(r) { return {host: r.host, ip: r.server, client: r.client}; }

    function details(r) {
        var kv = [
            ['{{ lang._('Device') }}', r.client + (r.cport ? ':' + r.cport : '')],
            ['{{ lang._('Destination') }}', (r.host ? r.host + ' (' + r.server + ')' : r.server) + (r.sport ? ':' + r.sport : '')],
            ['{{ lang._('Protocol') }}', r.proto + ' / ' + r.state],
            ['{{ lang._('Direction') }}', r.direction],
            ['{{ lang._('Application') }}', (r.app || '-') + (r.category ? ' (' + r.category + ')' : '')],
            ['{{ lang._('AI service') }}', r.ai || '-'],
            ['{{ lang._('Country') }}', r.country ? L7.flag(r.country) + ' ' + r.country : '-'],
            ['{{ lang._('Decision') }}', (r.action || '-') + (r.policy ? ' by ' + r.policy : '')],
            ['{{ lang._('Age') }}', L7.dur(r.age) + ', {{ lang._('closes in') }} ' + L7.dur(r.expires)],
            ['{{ lang._('Data') }}', '{{ lang._('sent') }} ' + L7.bytes(r.up) + ' (' + L7.num(r.pup) + ' {{ lang._('packets') }}), {{ lang._('received') }} ' + L7.bytes(r.down) + ' (' + L7.num(r.pdown) + ' {{ lang._('packets') }})'],
            ['{{ lang._('Inspected by proxy') }}', r.proxied ? r.proxied : '{{ lang._('no') }}'],
            ['{{ lang._('Interface') }}', r.iface]
        ];
        var html = '<dl class="l7-kv">' + kv.map(function (p) { return '<dt>' + E(p[0]) + '</dt><dd>' + E(p[1]) + '</dd>'; }).join('') + '</dl>';
        BootstrapDialog.show({title: '{{ lang._('Session details') }}', message: html, buttons: [
            {label: '{{ lang._('Block') }}', cssClass: 'btn-danger', action: function (d) { d.close(); quick('block', ctxOfRow(r)); }},
            {label: '{{ lang._('Allow') }}', cssClass: 'btn-success', action: function (d) { d.close(); quick('allow', ctxOfRow(r)); }},
            {label: '{{ lang._('Close') }}', action: function (d) { d.close(); }}
        ]});
    }

    /* ---------------- events ---------------- */
    $('#tbl-conn').on('click', '.act-block', function () { quick('block', ctxOfRow(S.view[$(this).data('i')])); });
    $('#tbl-conn').on('click', '.act-allow', function () { quick('allow', ctxOfRow(S.view[$(this).data('i')])); });
    $('#tbl-conn').on('click', '.act-info', function () { details(S.view[$(this).data('i')]); });
    $('#tbl-sites').on('click', '.site-block', function () { var d = S.sites[$(this).data('i')]; quick('block', {host: d.host, ip: d.server}); });
    $('#tbl-sites').on('click', '.site-allow', function () { var d = S.sites[$(this).data('i')]; quick('allow', {host: d.host, ip: d.server}); });
    $('#tbl-blocked').on('click', '.rec-allow', function () { var r = S.recent[$(this).data('i')]; quick('allow', {host: r.host, ip: r.server}); });
    $('#tbl-devices').on('click', '.act-filter', function () {
        $('#live-q').val($(this).data('q')).trigger('input');
        $('a[href="#tab-conn"]').tab('show');
    });
    $('#tbl-conn thead').on('click', 'th.sortable', function () {
        var k = $(this).data('sort');
        S.sort = {key: k, dir: S.sort.key === k ? -S.sort.dir : (k === 'rdown' || k === 'rup' || k === 'total' ? -1 : 1)};
        render();
    });
    $('.l7-chip').on('click', function () {
        var d = $(this).data('dir');
        S.dirs[d] = !S.dirs[d];
        $(this).toggleClass('on', S.dirs[d]);
        poll();
    });
    var qTimer = null;
    $('#live-q').on('input', function () {
        clearTimeout(qTimer);
        var v = $(this).val();
        qTimer = setTimeout(function () { S.q = v.replace(/[^A-Za-z0-9._:\/ -]/g, ''); poll(); }, 350);
    });
    $('#live-every').on('change', function () { S.every = parseInt($(this).val(), 10); schedule(); });
    $('#live-pause').on('click', function () {
        S.paused = !S.paused;
        $(this).find('i').attr('class', 'fa fa-' + (S.paused ? 'play' : 'pause'));
        $(this).find('span').text(S.paused ? '{{ lang._('Resume') }}' : '{{ lang._('Pause') }}');
        $('#live-foot').text(S.paused ? '{{ lang._('Paused. Click Resume to continue.') }}' : '');
        if (!S.paused) { poll(); }
    });
    $('a[href="#tab-blocked"]').on('shown.bs.tab', loadRecent);

    /* ---------------- history (stored flows) ---------------- */
    var historyHooked = false;
    function setupHistory() {
        if (historyHooked) { return; }
        historyHooked = true;
        var grid = $('#grid-flows').UIBootgrid({
            search: '/api/layer7security/flows/search',
            options: {
                rowCount: [25, 50, 100, 250],
                requestHandler: function (request) {
                    request.period = $('#flow-period').val();
                    request.only = $('#flow-blocked').is(':checked') ? 'blocked' : 'all';
                    return request;
                },
                formatters: {
                    time: function (column, row) { return E(new Date(row.ts_end * 1000).toLocaleString()); },
                    bytes: function (column, row) { return E(L7.bytes(row[column.id])); },
                    site: function (column, row) { return E(row.host || row.server); },
                    action: function (column, row) {
                        return row.action === 'block' ? L7.tag('{{ lang._('Blocked') }}', 'block') : (row.action === 'allow' ? L7.tag('{{ lang._('Allowed') }}', 'allow') : '<span class="l7-muted">-</span>');
                    },
                    cmds: function (column, row) {
                        return '<span class="l7-act"><button class="btn btn-xs btn-danger hist-block" data-host="' + E(row.host) + '" data-ip="' + E(row.server) + '" data-client="' + E(row.client) + '"><i class="fa fa-ban"></i></button> ' +
                            '<button class="btn btn-xs btn-success hist-allow" data-host="' + E(row.host) + '" data-ip="' + E(row.server) + '" data-client="' + E(row.client) + '"><i class="fa fa-check"></i></button></span>';
                    }
                }
            }
        });
        $('#flow-period, #flow-blocked').on('change', function () { $('#grid-flows').bootgrid('reload'); });
        $('#grid-flows').on('click', '.hist-block', function () { quick('block', {host: $(this).data('host'), ip: $(this).data('ip'), client: $(this).data('client')}); });
        $('#grid-flows').on('click', '.hist-allow', function () { quick('allow', {host: $(this).data('host'), ip: $(this).data('ip')}); });
    }
    $('a[href="#tab-history"]').on('shown.bs.tab', setupHistory);

    poll();
    schedule();
    loadRecent();
    setInterval(function () { if ($('#tab-blocked').hasClass('active')) { loadRecent(); } }, 10000);
});
</script>
