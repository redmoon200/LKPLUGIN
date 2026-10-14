<div class="l7">
    {{ partial('OPNsense/Layer7Security/partials/header', [
        'title': lang._('Content Filtering (CFS)'),
        'subtitle': lang._('Keep unwanted website categories, known bad addresses and unsafe search results away from your network.'),
        'icon': 'filter',
        'accent': 'prot',
        'apply': true
    ]) }}

    <div class="l7-tiles" id="cfs-tiles"></div>

    <ul class="nav nav-tabs" role="tablist">
        <li class="active"><a data-toggle="tab" href="#tab-overview">{{ lang._('Overview') }}</a></li>
        <li><a data-toggle="tab" href="#tab-cats">{{ lang._('Categories') }}</a></li>
        <li><a data-toggle="tab" href="#tab-rules">{{ lang._('Group rules') }}</a></li>
        <li><a data-toggle="tab" href="#tab-settings">{{ lang._('Settings') }}</a></li>
        <li><a data-toggle="tab" href="#tab-test">{{ lang._('Test a website') }}</a></li>
        <li><a data-toggle="tab" href="#tab-activity">{{ lang._('Activity') }}</a></li>
    </ul>

    <div class="tab-content">
        <div id="tab-overview" class="tab-pane fade in active">
            <div id="cfs-switch"></div>
            <div class="l7-grid2">
                <div class="l7-card">
                    <h3>{{ lang._('Blocked categories') }}</h3>
                    <div id="cfs-ov-cats"></div>
                </div>
                <div class="l7-card">
                    <h3>{{ lang._('Extra protection') }}</h3>
                    <div id="cfs-ov-extra"></div>
                </div>
            </div>
        </div>

        <div id="tab-cats" class="tab-pane fade">
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-cats">
                    <thead><tr><th style="width:3em">{{ lang._('Block') }}</th><th>{{ lang._('Category') }}</th><th>{{ lang._('What it covers') }}</th><th class="num">{{ lang._('Websites listed') }}</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
            <button class="btn btn-primary" id="cats-save" type="button" style="margin-top:12px"><i class="fa fa-save"></i> {{ lang._('Save categories') }}</button>
        </div>

        <div id="tab-rules" class="tab-pane fade">
            <table id="grid-cfsrules" class="table table-condensed table-hover table-striped" data-editDialog="DialogCfsRule" data-editAlert="l7-pending">
                <thead>
                    <tr>
                        <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                        <th data-column-id="enabled" data-width="5em" data-type="string" data-formatter="rowtoggle">{{ lang._('On') }}</th>
                        <th data-column-id="sequence" data-width="5em" data-type="numeric">{{ lang._('Order') }}</th>
                        <th data-column-id="name" data-type="string">{{ lang._('Name') }}</th>
                        <th data-column-id="action" data-width="6em" data-formatter="act">{{ lang._('Action') }}</th>
                        <th data-column-id="dnsCategories" data-type="string">{{ lang._('Categories') }}</th>
                        <th data-column-id="interfaces" data-type="string">{{ lang._('Networks') }}</th>
                        <th data-column-id="sources" data-type="string">{{ lang._('Devices') }}</th>
                        <th data-column-id="users" data-type="string">{{ lang._('Users') }}</th>
                        <th data-column-id="startTime" data-width="5em" data-type="string">{{ lang._('From') }}</th>
                        <th data-column-id="endTime" data-width="5em" data-type="string">{{ lang._('Until') }}</th>
                        <th data-column-id="commands" data-width="8em" data-formatter="commands" data-sortable="false">{{ lang._('Edit') }}</th>
                    </tr>
                </thead>
                <tbody></tbody>
                <tfoot>
                    <tr>
                        <td></td>
                        <td colspan="11">
                            <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-fw fa-plus"></span> {{ lang._('Add group rule') }}</button>
                            <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-fw fa-trash-o"></span></button>
                        </td>
                    </tr>
                </tfoot>
            </table>
        </div>

        <div id="tab-settings" class="tab-pane fade">
            {{ partial("layout_partials/base_form", ['fields': cfsForm, 'id': 'frm_cfs']) }}
            <button class="btn btn-primary" id="cfs-save" type="button"><i class="fa fa-save"></i> {{ lang._('Save') }}</button>
        </div>

        <div id="tab-test" class="tab-pane fade">
            <div class="l7-card">
                <h3>{{ lang._('Which category is this website in?') }}</h3>
                <div class="l7-toolbar">
                    <input type="text" id="cfs-test-q" class="form-control grow" placeholder="www.example.com" maxlength="200"/>
                    <button class="btn btn-primary" id="cfs-test-go" type="button"><i class="fa fa-search"></i> {{ lang._('Check') }}</button>
                </div>
                <div id="cfs-test-out"></div>
            </div>
        </div>

        <div id="tab-activity" class="tab-pane fade">
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-cfslog">
                    <thead><tr><th>{{ lang._('Time') }}</th><th>{{ lang._('Device') }}</th><th>{{ lang._('Website asked for') }}</th><th>{{ lang._('Category') }}</th><th>{{ lang._('Action') }}</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogCfsRule, 'id': 'DialogCfsRule', 'label': lang._('Group rule')]) }}

<script>
$(document).ready(function () {
    var E = L7.esc, ST = {}, LOG = [];
    var CATS = [
        {id: 'ads', name: '{{ lang._('Advertising') }}', desc: '{{ lang._('Ad servers and banners') }}'},
        {id: 'trackers', name: '{{ lang._('Trackers') }}', desc: '{{ lang._('Analytics and tracking services') }}'},
        {id: 'malware', name: '{{ lang._('Malware') }}', desc: '{{ lang._('Sites that spread viruses and unwanted software') }}'},
        {id: 'phishing', name: '{{ lang._('Phishing') }}', desc: '{{ lang._('Fake sites that steal passwords') }}'},
        {id: 'botnet', name: '{{ lang._('Botnets') }}', desc: '{{ lang._('Servers that control infected computers') }}'},
        {id: 'adult', name: '{{ lang._('Adult content') }}', desc: '{{ lang._('Pornography') }}'},
        {id: 'gambling', name: '{{ lang._('Gambling') }}', desc: '{{ lang._('Casinos and betting') }}'},
        {id: 'social', name: '{{ lang._('Social networks') }}', desc: '{{ lang._('Facebook, Instagram, TikTok and similar') }}'},
        {id: 'streaming', name: '{{ lang._('Streaming media') }}', desc: '{{ lang._('Video and music services') }}'},
        {id: 'games', name: '{{ lang._('Games') }}', desc: '{{ lang._('Online games and game stores') }}'}
    ];
    var NAME = {}; CATS.forEach(function (c) { NAME[c.id] = c.name; });

    L7.applyButton('#reconfigureAct', function () { load(); }, ['frm_cfs']);
    L7.rememberTabs('cfs');
    L7.engineStatus('#l7-engine-pill');

    mapDataToFormUI({'frm_cfs': '/api/layer7security/settings/get'}).done(function () { $('.selectpicker').selectpicker('refresh'); });
    $('#cfs-save').on('click', function () {
        saveFormToEndpoint('/api/layer7security/settings/set', 'frm_cfs', function () { L7.pending(); load(); L7.toast('{{ lang._('Saved. Click Apply changes to activate.') }}'); });
    });

    $('#grid-cfsrules').UIBootgrid({
        search: '/api/layer7security/settings/search_policy',
        get: '/api/layer7security/settings/get_policy/',
        set: '/api/layer7security/settings/set_policy/',
        add: '/api/layer7security/settings/add_cfs/',
        del: '/api/layer7security/settings/del_policy/',
        toggle: '/api/layer7security/settings/toggle_policy/',
        options: {
            requestHandler: function (request) { request.module = 'cfs'; return request; },
            formatters: { act: function (c, row) { return L7.tag(row.action === 'allow' ? '{{ lang._('Allow') }}' : '{{ lang._('Block') }}', row.action); } }
        }
    });

    function sum(o) { return Object.keys(o || {}).reduce(function (a, k) { return a + (o[k] || 0); }, 0); }

    function load() {
        L7.get('/api/layer7security/cfs/status').done(function (d) {
            ST = d || {};
            var on = !!ST.enabled;
            $('#l7-module-pill').replaceWith($(L7.pill(on ? '{{ lang._('Filtering on') }}' : '{{ lang._('Filtering off') }}', on ? 'ok' : 'warn')).attr('id', 'l7-module-pill'));
            var cats = ST.categories || [];
            var listed = 0;
            (ST.lists || []).forEach(function (l) { if (cats.indexOf(l.category) >= 0) { listed += l.feed + l.seed; } });
            var threat = 0;
            (ST.ips || []).forEach(function (l) { if (l.enabled) { threat += l.entries; } });
            $('#cfs-tiles').html(
                L7.tile(on ? '{{ lang._('On') }}' : '{{ lang._('Off') }}', '{{ lang._('Content filtering') }}', '', on ? 'ok' : 'warn') +
                L7.tile(cats.length, '{{ lang._('Categories blocked') }}') +
                L7.tile(L7.num(listed), '{{ lang._('Websites listed') }}') +
                L7.tile(L7.num(threat), '{{ lang._('Bad addresses blocked') }}') +
                L7.tile(ST.safeSearch ? '{{ lang._('On') }}' : '{{ lang._('Off') }}', '{{ lang._('Safe search') }}') +
                L7.tile(L7.num(LOG.length), '{{ lang._('Refused in 24 h') }}', '', LOG.length ? 'warn' : '')
            );
            $('#cfs-switch').html(on ?
                '<div class="l7-hint ok"><strong>{{ lang._('Content filtering is on.') }}</strong> <button class="btn btn-xs btn-default" id="cfs-off">{{ lang._('Turn off') }}</button></div>' :
                '<div class="l7-hint warn"><strong>{{ lang._('Content filtering is off.') }}</strong> {{ lang._('Nothing is blocked by category yet.') }} <button class="btn btn-xs btn-primary" id="cfs-on">{{ lang._('Turn on') }}</button></div>');
            $('#cfs-ov-cats').html(cats.length ? '<ul style="padding-left:18px">' + cats.map(function (c) { return '<li>' + E(NAME[c] || c) + '</li>'; }).join('') + '</ul>' : L7.empty('filter', '{{ lang._('No category is blocked. Choose some under Categories.') }}'));
            var extra = [];
            extra.push((ST.safeSearch ? '<i class="fa fa-check" style="color:var(--l7-ok)"></i> ' : '<i class="fa fa-times l7-muted"></i> ') + '{{ lang._('Safe search') }}');
            extra.push((ST.youtube && ST.youtube !== 'off' ? '<i class="fa fa-check" style="color:var(--l7-ok)"></i> ' : '<i class="fa fa-times l7-muted"></i> ') + '{{ lang._('YouTube restricted mode') }}' + (ST.youtube && ST.youtube !== 'off' ? ' (' + E(ST.youtube) + ')' : ''));
            extra.push((ST.threatIps && ST.threatIps.length ? '<i class="fa fa-check" style="color:var(--l7-ok)"></i> ' : '<i class="fa fa-times l7-muted"></i> ') + '{{ lang._('Bad address lists') }}' + (ST.threatIps && ST.threatIps.length ? ' (' + E(ST.threatIps.join(', ')) + ')' : ''));
            $('#cfs-ov-extra').html(extra.map(function (x) { return '<div style="margin:6px 0">' + x + '</div>'; }).join(''));
            renderCats();
        });
    }

    function renderCats() {
        var counts = {};
        (ST.lists || []).forEach(function (l) { counts[l.category] = (l.feed || 0) + (l.seed || 0); });
        var on = ST.categories || [];
        $('#tbl-cats tbody').html(CATS.map(function (c) {
            return '<tr><td><input type="checkbox" class="cat-on" data-id="' + c.id + '"' + (on.indexOf(c.id) >= 0 ? ' checked' : '') + '></td><td><strong>' + E(c.name) + '</strong></td><td>' + E(c.desc) + '</td><td class="num">' + L7.num(counts[c.id] || 0) + '</td></tr>';
        }).join(''));
    }

    $('#tab-overview').on('click', '#cfs-on, #cfs-off', function () {
        var turn = this.id === 'cfs-on' ? '1' : '0';
        $(this).prop('disabled', true).text('...');
        L7.post('/api/layer7security/settings/set', {layer7security: {general: {dnsFilter: turn}}}).done(function () {
            L7.apply().done(function (r) {
                if (r && r.status === 'failed') { L7.toast(r.message || 'Apply failed', 'bad'); } else { L7.toast(turn === '1' ? '{{ lang._('Content filtering is on.') }}' : '{{ lang._('Content filtering is off.') }}'); }
                load();
            });
        });
    });

    $('#cats-save').on('click', function () {
        var ids = $('.cat-on:checked').map(function () { return $(this).data('id'); }).get();
        L7.post('/api/layer7security/settings/set', {layer7security: {general: {dnsCategories: ids.join(',')}}}).done(function (r) {
            if (r && r.result === 'saved') { L7.pending(); L7.toast('{{ lang._('Saved. Click Apply changes to activate.') }}'); load(); }
            else { L7.toast('{{ lang._('Could not save.') }}', 'bad'); }
        });
    });

    function test() {
        var q = $('#cfs-test-q').val();
        if (!q) { return; }
        L7.post('/api/layer7security/cfs/lookup', {q: q}).done(function (d) {
            var h;
            if (d.error) { h = '<div class="l7-hint warn">' + E(d.error) + '</div>'; }
            else if (!d.matches || !d.matches.length) { h = '<div class="l7-hint ok"><strong>' + E(d.query) + '</strong> {{ lang._('is not in any category list.') }}</div>'; }
            else {
                var cats = ST.categories || [];
                h = '<div class="l7-hint"><strong>' + E(d.query) + '</strong> {{ lang._('is listed in:') }}</div><table class="l7-table"><thead><tr><th>{{ lang._('Category') }}</th><th>{{ lang._('Listed as') }}</th><th>{{ lang._('Source') }}</th><th>{{ lang._('Blocked now') }}</th></tr></thead><tbody>' +
                    d.matches.map(function (m) {
                        var blocked = cats.indexOf(m.category) >= 0 && ST.enabled;
                        return '<tr><td>' + E(NAME[m.category] || m.category) + '</td><td class="mono">' + E(m.entry) + '</td><td>' + E(m.list) + '</td><td>' + (blocked ? L7.tag('{{ lang._('yes') }}', 'block') : '<span class="l7-muted">{{ lang._('no') }}</span>') + '</td></tr>';
                    }).join('') + '</tbody></table>';
            }
            $('#cfs-test-out').html(h);
        });
    }
    $('#cfs-test-go').on('click', test);
    $('#cfs-test-q').on('keydown', function (e) { if (e.which === 13) { test(); } });

    function loadLog() {
        L7.get('/api/layer7security/cfs/log', {module: 'cfs', minutes: 1440, limit: 200}).done(function (d) {
            LOG = (d && d.rows) || [];
            $('#tbl-cfslog tbody').html(LOG.map(function (r, i) {
                return '<tr><td title="' + E(L7.when(r.ts)) + '">' + E(L7.ago(r.ts)) + '</td><td class="mono">' + E(r.client) + '</td><td class="trunc">' + E(r.query) + '</td><td>' + E(NAME[r.category] || r.category) + '</td>' +
                    '<td><button class="btn btn-xs btn-success cfs-allow" data-i="' + i + '"><i class="fa fa-check"></i> {{ lang._('Allow') }}</button></td></tr>';
            }).join('') || '<tr><td colspan="5">' + L7.empty('check-circle', '{{ lang._('Nothing was refused yet.') }}') + '</td></tr>');
        });
    }
    $('#tbl-cfslog').on('click', '.cfs-allow', function () {
        var r = LOG[$(this).data('i')];
        L7.confirm({title: '{{ lang._('Allow this website?') }}', message: E('{{ lang._('Always allow') }} ' + r.query + '?'), yes: '{{ lang._('Allow') }}', onYes: function () {
            L7.post('/api/layer7security/webcontrol/quick', {kind: 'domain', value: r.query, action: 'allow', minutes: 0, note: 'from content filtering'}).done(function (res) {
                L7.toast(res && res.result === 'saved' ? '{{ lang._('Allowed and active.') }}' : ((res && res.message) || '{{ lang._('Failed') }}'), res && res.result === 'saved' ? '' : 'bad');
            });
        }});
    });
    $('a[href="#tab-activity"]').on('shown.bs.tab', loadLog);

    load();
    loadLog();
});
</script>
