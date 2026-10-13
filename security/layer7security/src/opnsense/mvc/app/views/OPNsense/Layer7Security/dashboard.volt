<script src="{{ cache_safe('/ui/js/chart.umd.min.js') }}"></script>
<style>
    .l7-tiles { display: flex; flex-wrap: wrap; gap: 12px; margin: 10px 0 18px 0; }
    .l7-tile { flex: 1 1 150px; border: 1px solid rgba(128,128,128,.35); border-radius: 4px; padding: 10px 14px; }
    .l7-tile .v { font-size: 26px; font-weight: 600; line-height: 1.2; }
    .l7-tile .k { opacity: .7; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
    .l7-grid { display: flex; flex-wrap: wrap; gap: 18px; }
    .l7-card { flex: 1 1 420px; min-width: 300px; }
    .l7-card h3 { margin: 0 0 8px 0; font-size: 15px; }
    .l7-chart { position: relative; height: 260px; }
    .l7-bar { height: 6px; border-radius: 3px; background: #4e79a7; }
    .l7-muted { opacity: .65; }
    .l7-pill { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 12px; }
    .l7-ok { background: #2e7d32; color: #fff; }
    .l7-bad { background: #c62828; color: #fff; }
    .l7-toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
</style>

<div class="content-box" style="padding: 15px;">
    <div class="l7-toolbar">
        <strong>{{ lang._('Period') }}</strong>
        <select id="l7-period" class="selectpicker" data-width="auto">
            <option value="300">{{ lang._('Last 5 minutes') }}</option>
            <option value="3600" selected="selected">{{ lang._('Last hour') }}</option>
            <option value="21600">{{ lang._('Last 6 hours') }}</option>
            <option value="86400">{{ lang._('Last 24 hours') }}</option>
            <option value="604800">{{ lang._('Last 7 days') }}</option>
        </select>
        <span id="l7-engine" class="l7-pill l7-bad">{{ lang._('engine: unknown') }}</span>
        <span id="l7-engine-info" class="l7-muted"></span>
    </div>

    <div class="l7-tiles">
        <div class="l7-tile"><div class="v" id="t-flows">-</div><div class="k">{{ lang._('Flows') }}</div></div>
        <div class="l7-tile"><div class="v" id="t-clients">-</div><div class="k">{{ lang._('Clients') }}</div></div>
        <div class="l7-tile"><div class="v" id="t-apps">-</div><div class="k">{{ lang._('Applications') }}</div></div>
        <div class="l7-tile"><div class="v" id="t-down">-</div><div class="k">{{ lang._('Downloaded') }}</div></div>
        <div class="l7-tile"><div class="v" id="t-up">-</div><div class="k">{{ lang._('Uploaded') }}</div></div>
        <div class="l7-tile"><div class="v" id="t-blocked">-</div><div class="k">{{ lang._('Blocked flows') }}</div></div>
    </div>

    <div class="l7-grid">
        <div class="l7-card" style="flex-basis: 100%;">
            <h3>{{ lang._('Traffic over time') }}</h3>
            <div class="l7-chart"><canvas id="c-timeline"></canvas></div>
        </div>
        <div class="l7-card">
            <h3>{{ lang._('Top applications by volume') }}</h3>
            <div class="l7-chart"><canvas id="c-apps"></canvas></div>
        </div>
        <div class="l7-card">
            <h3>{{ lang._('Categories') }}</h3>
            <div class="l7-chart"><canvas id="c-cats"></canvas></div>
        </div>
        <div class="l7-card">
            <h3>{{ lang._('Top countries by volume') }}</h3>
            <div class="l7-chart"><canvas id="c-countries"></canvas></div>
            <div class="l7-muted" id="countries-empty" style="display: none;">{{ lang._('No country data yet: enable GeoIP and update the database.') }}</div>
        </div>
        <div class="l7-card">
            <h3>{{ lang._('Top clients') }}</h3>
            <table class="table table-condensed table-striped" id="tbl-clients">
                <thead><tr><th>{{ lang._('Client') }}</th><th>{{ lang._('Flows') }}</th><th>{{ lang._('Down') }}</th><th>{{ lang._('Up') }}</th><th>{{ lang._('Blocked') }}</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>
        <div class="l7-card">
            <h3>{{ lang._('Policy blocks') }}</h3>
            <table class="table table-condensed table-striped" id="tbl-blocks">
                <thead><tr><th>{{ lang._('Policy') }}</th><th>{{ lang._('Application') }}</th><th>{{ lang._('Category') }}</th><th>{{ lang._('Hits') }}</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>
    </div>
</div>

<script>
    $(document).ready(function () {
        const palette = ['#4e79a7', '#f28e2b', '#59a14f', '#e15759', '#76b7b2', '#edc948', '#b07aa1', '#ff9da7', '#9c755f', '#bab0ac', '#86bcb6', '#d37295'];
        const charts = {};
        let timer = null;

        function esc(value) {
            return $('<div>').text(value === null || value === undefined ? '' : String(value)).html();
        }
        function bytes(n) {
            n = Number(n) || 0;
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            let i = 0;
            while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
            return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + ' ' + units[i];
        }
        function period() { return $('#l7-period').val(); }

        function chart(id, config) {
            if (charts[id]) { charts[id].destroy(); }
            charts[id] = new Chart(document.getElementById(id), config);
        }

        function loadEngine() {
            ajaxGet('/api/layer7security/dashboard/engine', {}, function (d) {
                const ok = d && d.running;
                $('#l7-engine').toggleClass('l7-ok', !!ok).toggleClass('l7-bad', !ok)
                    .text(ok ? '{{ lang._("engine running") }}' : '{{ lang._("engine stopped") }}');
                $('#l7-engine-info').text(ok ? (d.flows_active + ' {{ lang._("active flows") }}, ' + d.packets + ' {{ lang._("packets") }}, ' + d.blocks + ' {{ lang._("blocks") }}') : '');
            });
        }

        function loadSummary() {
            ajaxGet('/api/layer7security/dashboard/summary', { period: period() }, function (d) {
                if (!d || d.error) { return; }
                $('#t-flows').text(d.flows);
                $('#t-clients').text(d.clients);
                $('#t-apps').text(d.apps);
                $('#t-down').text(bytes(d.down));
                $('#t-up').text(bytes(d.up));
                $('#t-blocked').text((d.blocked || 0) + (d.events ? ' / ' + d.events : ''));
            });
        }

        function loadTimeline() {
            ajaxGet('/api/layer7security/dashboard/timeline', { period: period() }, function (d) {
                if (!d || !d.rows) { return; }
                const labels = d.rows.map(function (r) {
                    const t = new Date(r.t * 1000);
                    return period() > 86400 ? t.toLocaleString() : t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                });
                chart('c-timeline', {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [
                            { label: '{{ lang._("Down") }}', data: d.rows.map(function (r) { return r.down; }), backgroundColor: palette[0], stack: 's' },
                            { label: '{{ lang._("Up") }}', data: d.rows.map(function (r) { return r.up; }), backgroundColor: palette[1], stack: 's' }
                        ]
                    },
                    options: {
                        maintainAspectRatio: false,
                        animation: false,
                        scales: { x: { stacked: true }, y: { stacked: true, ticks: { callback: function (v) { return bytes(v); } } } },
                        plugins: { tooltip: { callbacks: { label: function (c) { return c.dataset.label + ': ' + bytes(c.parsed.y); } } } }
                    }
                });
            });
        }

        function loadApps() {
            ajaxGet('/api/layer7security/dashboard/apps', { period: period() }, function (d) {
                if (!d || !d.rows) { return; }
                chart('c-apps', {
                    type: 'bar',
                    data: {
                        labels: d.rows.map(function (r) { return r.app; }),
                        datasets: [{ data: d.rows.map(function (r) { return r.bytes; }), backgroundColor: palette[0] }]
                    },
                    options: {
                        indexAxis: 'y', maintainAspectRatio: false, animation: false,
                        plugins: { legend: { display: false }, tooltip: { callbacks: { label: function (c) { return bytes(c.parsed.x); } } } },
                        scales: { x: { ticks: { callback: function (v) { return bytes(v); } } } }
                    }
                });
            });
        }

        function loadCats() {
            ajaxGet('/api/layer7security/dashboard/categories', { period: period() }, function (d) {
                if (!d || !d.rows) { return; }
                chart('c-cats', {
                    type: 'doughnut',
                    data: {
                        labels: d.rows.map(function (r) { return r.category; }),
                        datasets: [{ data: d.rows.map(function (r) { return r.bytes; }), backgroundColor: palette }]
                    },
                    options: {
                        maintainAspectRatio: false, animation: false,
                        plugins: { legend: { position: 'right' }, tooltip: { callbacks: { label: function (c) { return c.label + ': ' + bytes(c.parsed); } } } }
                    }
                });
            });
        }

        function flag(cc) {
            if (!/^[A-Z]{2}$/.test(cc)) { return ''; }
            return String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65) + ' ';
        }

        function loadCountries() {
            ajaxGet('/api/layer7security/dashboard/countries', { period: period() }, function (d) {
                if (!d || !d.rows) { return; }
                $('#countries-empty').toggle(d.rows.length === 0);
                chart('c-countries', {
                    type: 'bar',
                    data: {
                        labels: d.rows.map(function (r) { return flag(r.country) + r.country; }),
                        datasets: [{ data: d.rows.map(function (r) { return r.bytes; }), backgroundColor: palette[2] }]
                    },
                    options: {
                        indexAxis: 'y', maintainAspectRatio: false, animation: false,
                        plugins: { legend: { display: false }, tooltip: { callbacks: { label: function (c) { return bytes(c.parsed.x); } } } },
                        scales: { x: { ticks: { callback: function (v) { return bytes(v); } } } }
                    }
                });
            });
        }

        function loadClients() {
            ajaxGet('/api/layer7security/dashboard/clients', { period: period() }, function (d) {
                const body = $('#tbl-clients tbody').empty();
                if (!d || !d.rows) { return; }
                d.rows.forEach(function (r) {
                    body.append('<tr><td>' + esc(r.client) + '</td><td>' + esc(r.flows) + '</td><td>' + bytes(r.down) +
                        '</td><td>' + bytes(r.up) + '</td><td>' + esc(r.blocked || 0) + '</td></tr>');
                });
            });
        }

        function loadBlocks() {
            ajaxGet('/api/layer7security/dashboard/blocks', { period: period() }, function (d) {
                const body = $('#tbl-blocks tbody').empty();
                if (!d || !d.rows) { return; }
                if (d.rows.length === 0) {
                    body.append('<tr><td colspan="4" class="l7-muted">{{ lang._("No blocks in this period.") }}</td></tr>');
                }
                d.rows.forEach(function (r) {
                    body.append('<tr><td>' + esc(r.policy) + '</td><td>' + esc(r.app) + '</td><td>' + esc(r.category) +
                        '</td><td>' + esc(r.hits) + '</td></tr>');
                });
            });
        }

        function refresh() {
            loadEngine(); loadSummary(); loadTimeline(); loadApps(); loadCats(); loadCountries(); loadClients(); loadBlocks();
        }

        $('#l7-period').on('change', refresh);
        refresh();
        timer = setInterval(refresh, 15000);
        $(window).on('beforeunload', function () { if (timer) { clearInterval(timer); } });
    });
</script>
