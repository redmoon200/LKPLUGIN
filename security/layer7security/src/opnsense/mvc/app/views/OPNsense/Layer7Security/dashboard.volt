<script src="{{ cache_safe('/ui/js/chart.umd.min.js') }}"></script>
<div class="l7">
    {{ partial('OPNsense/Layer7Security/partials/header', [
        'title': lang._('Layer 7 Overview'),
        'subtitle': lang._('What your network is doing, what is protected, and what was stopped.'),
        'icon': 'tachometer',
        'accent': 'con',
        'apply': false
    ]) }}

    <div class="l7-toolbar">
        <strong>{{ lang._('Period') }}</strong>
        <select id="l7-period" class="form-control" style="width:auto">
            <option value="300">{{ lang._('Last 5 minutes') }}</option>
            <option value="3600" selected="selected">{{ lang._('Last hour') }}</option>
            <option value="21600">{{ lang._('Last 6 hours') }}</option>
            <option value="86400">{{ lang._('Last 24 hours') }}</option>
            <option value="604800">{{ lang._('Last 7 days') }}</option>
        </select>
        <span class="l7-muted" id="l7-engine-info"></span>
        <a class="btn btn-default" href="/ui/layer7security/live"><i class="fa fa-eye"></i> {{ lang._('Open live sessions') }}</a>
    </div>

    <div class="l7-card">
        <h3>{{ lang._('Protection status') }}</h3>
        <div class="l7-tiles" id="mod-tiles" style="margin-bottom:0"></div>
    </div>

    <div class="l7-tiles" id="l7-tiles">
        <div id="t-flows"></div>
    </div>

    <div class="l7-grid2">
        <div class="l7-card" style="grid-column:1/-1"><h3>{{ lang._('Traffic over time') }}</h3><div style="position:relative;height:240px"><canvas id="c-timeline"></canvas></div></div>
        <div class="l7-card"><h3>{{ lang._('Top applications by volume') }}</h3><div style="position:relative;height:260px"><canvas id="c-apps"></canvas></div></div>
        <div class="l7-card"><h3>{{ lang._('Categories') }}</h3><div style="position:relative;height:260px"><canvas id="c-cats"></canvas></div></div>
        <div class="l7-card"><h3>{{ lang._('Top countries by volume') }}</h3><div style="position:relative;height:260px"><canvas id="c-countries"></canvas></div>
            <div class="l7-muted" id="countries-empty" style="display:none">{{ lang._('No country data yet: turn on GeoIP and update the database.') }}</div></div>
        <div class="l7-card"><h3>{{ lang._('Busiest devices') }}</h3>
            <table class="l7-table" id="tbl-clients"><thead><tr><th>{{ lang._('Device') }}</th><th class="num">{{ lang._('Connections') }}</th><th class="num">{{ lang._('Download') }}</th><th class="num">{{ lang._('Upload') }}</th><th class="num">{{ lang._('Blocked') }}</th></tr></thead><tbody></tbody></table></div>
        <div class="l7-card"><h3>{{ lang._('What was stopped') }}</h3>
            <table class="l7-table" id="tbl-blocks"><thead><tr><th>{{ lang._('Rule') }}</th><th>{{ lang._('Application') }}</th><th>{{ lang._('Category') }}</th><th class="num">{{ lang._('Times') }}</th></tr></thead><tbody></tbody></table></div>
    </div>
</div>

<script>
$(document).ready(function () {
    var E = L7.esc, charts = {}, palette = ['#4e79a7', '#f28e2b', '#59a14f', '#e15759', '#76b7b2', '#edc948', '#b07aa1', '#ff9da7', '#9c755f', '#bab0ac', '#86bcb6', '#d37295'];
    var MODS = {web: ['Web Control', 'globe'], app: ['Application Control', 'th-large'], cfs: ['Content Filtering', 'filter'], dpi: ['DPI-SSL', 'lock'], av: ['Antivirus', 'bug'],
                ai: ['AI Service', 'microchip'], inspect: ['AI Inspection', 'search'], audit: ['AI Audit', 'book'], auth: ['Sign-in', 'users']};
    L7.engineStatus('#l7-engine-pill');
    $('#l7-module-pill').remove();

    function period() { return $('#l7-period').val(); }
    function chart(id, config) {
        if (charts[id]) { charts[id].destroy(); }
        charts[id] = new Chart(document.getElementById(id), config);
    }

    function loadModules() {
        L7.get('/api/layer7security/dashboard/modules').done(function (d) {
            if (!d || !d.modules) { return; }
            $('#mod-tiles').html(Object.keys(MODS).map(function (k) {
                var m = d.modules[k] || {};
                return '<a href="' + E(m.url) + '" style="text-decoration:none;color:inherit"><div class="l7-tile ' + (m.on ? 'ok' : '') + '"><div class="v" style="font-size:16px"><i class="fa fa-' + MODS[k][1] + '"></i> ' + E(MODS[k][0]) + '</div>' +
                    '<div class="l" style="margin-top:6px">' + (m.on ? '{{ lang._('On') }}' : '{{ lang._('Off') }}') + '</div><div class="s">' + E(m.detail || '') + '</div></div></a>';
            }).join(''));
        });
    }

    function loadEngine() {
        L7.get('/api/layer7security/dashboard/engine').done(function (d) {
            $('#l7-engine-info').text(d && d.running ? (d.flows_active + ' {{ lang._('active flows') }}, ' + d.packets + ' {{ lang._('packets') }}, ' + d.blocks + ' {{ lang._('blocks') }}') : '');
        });
    }

    function loadSummary() {
        L7.get('/api/layer7security/dashboard/summary', {period: period()}).done(function (d) {
            if (!d || d.error) { return; }
            $('#l7-tiles').html(
                L7.tile(L7.num(d.flows), '{{ lang._('Connections') }}') +
                L7.tile(L7.num(d.clients), '{{ lang._('Devices') }}') +
                L7.tile(L7.num(d.apps), '{{ lang._('Applications') }}') +
                L7.tile(L7.bytes(d.down), '{{ lang._('Downloaded') }}') +
                L7.tile(L7.bytes(d.up), '{{ lang._('Uploaded') }}') +
                L7.tile(L7.num(d.blocked || 0), '{{ lang._('Blocked connections') }}', '', d.blocked ? 'bad' : '')
            );
        });
    }

    function loadTimeline() {
        L7.get('/api/layer7security/dashboard/timeline', {period: period()}).done(function (d) {
            if (!d || !d.rows) { return; }
            var labels = d.rows.map(function (r) {
                var t = new Date(r.t * 1000);
                return period() > 86400 ? t.toLocaleString() : t.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
            });
            chart('c-timeline', {
                type: 'bar',
                data: {labels: labels, datasets: [
                    {label: '{{ lang._('Down') }}', data: d.rows.map(function (r) { return r.down; }), backgroundColor: palette[0], stack: 's'},
                    {label: '{{ lang._('Up') }}', data: d.rows.map(function (r) { return r.up; }), backgroundColor: palette[1], stack: 's'}]},
                options: {maintainAspectRatio: false, animation: false,
                    scales: {x: {stacked: true}, y: {stacked: true, ticks: {callback: function (v) { return L7.bytes(v); }}}},
                    plugins: {tooltip: {callbacks: {label: function (c) { return c.dataset.label + ': ' + L7.bytes(c.parsed.y); }}}}}
            });
        });
    }

    function hbar(id, url, label, color) {
        L7.get(url, {period: period()}).done(function (d) {
            if (!d || !d.rows) { return; }
            if (id === 'c-countries') { $('#countries-empty').toggle(d.rows.length === 0); }
            chart(id, {
                type: 'bar',
                data: {labels: d.rows.map(function (r) { return label(r); }), datasets: [{data: d.rows.map(function (r) { return r.bytes; }), backgroundColor: color}]},
                options: {indexAxis: 'y', maintainAspectRatio: false, animation: false,
                    plugins: {legend: {display: false}, tooltip: {callbacks: {label: function (c) { return L7.bytes(c.parsed.x); }}}},
                    scales: {x: {ticks: {callback: function (v) { return L7.bytes(v); }}}}}
            });
        });
    }

    function loadCats() {
        L7.get('/api/layer7security/dashboard/categories', {period: period()}).done(function (d) {
            if (!d || !d.rows) { return; }
            chart('c-cats', {
                type: 'doughnut',
                data: {labels: d.rows.map(function (r) { return r.category; }), datasets: [{data: d.rows.map(function (r) { return r.bytes; }), backgroundColor: palette}]},
                options: {maintainAspectRatio: false, animation: false,
                    plugins: {legend: {position: 'right'}, tooltip: {callbacks: {label: function (c) { return c.label + ': ' + L7.bytes(c.parsed); }}}}}
            });
        });
    }

    function loadClients() {
        L7.get('/api/layer7security/dashboard/clients', {period: period()}).done(function (d) {
            $('#tbl-clients tbody').html(((d && d.rows) || []).map(function (r) {
                return '<tr><td class="mono">' + E(r.client) + '</td><td class="num">' + L7.num(r.flows) + '</td><td class="num">' + L7.bytes(r.down) + '</td><td class="num">' + L7.bytes(r.up) + '</td><td class="num">' + L7.num(r.blocked || 0) + '</td></tr>';
            }).join('') || '<tr><td colspan="5">' + L7.empty('desktop', '{{ lang._('No traffic in this period.') }}') + '</td></tr>');
        });
    }

    function loadBlocks() {
        L7.get('/api/layer7security/dashboard/blocks', {period: period()}).done(function (d) {
            $('#tbl-blocks tbody').html(((d && d.rows) || []).map(function (r) {
                return '<tr><td>' + E(r.policy) + '</td><td>' + E(r.app) + '</td><td>' + E(r.category) + '</td><td class="num">' + L7.num(r.hits) + '</td></tr>';
            }).join('') || '<tr><td colspan="4">' + L7.empty('check-circle', '{{ lang._('Nothing was blocked in this period.') }}') + '</td></tr>');
        });
    }

    function refresh() {
        loadModules(); loadEngine(); loadSummary(); loadTimeline(); loadCats(); loadClients(); loadBlocks();
        hbar('c-apps', '/api/layer7security/dashboard/apps', function (r) { return r.app; }, palette[0]);
        hbar('c-countries', '/api/layer7security/dashboard/countries', function (r) { return L7.flag(r.country) + ' ' + r.country; }, palette[2]);
    }
    $('#l7-period').on('change', refresh);
    refresh();
    var timer = setInterval(refresh, 15000);
    $(window).on('beforeunload', function () { clearInterval(timer); });
});
</script>
