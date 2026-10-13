<div class="l7">
    {{ partial('OPNsense/Layer7Security/partials/header', [
        'title': lang._('AI Service'),
        'subtitle': lang._('See which AI services (ChatGPT, Claude, Gemini and more) are used, and allow, watch or block each one.'),
        'icon': 'microchip',
        'accent': 'ai',
        'apply': true
    ]) }}

    <div class="l7-tiles" id="ai-tiles"></div>

    <ul class="nav nav-tabs" role="tablist">
        <li class="active"><a data-toggle="tab" href="#usage">{{ lang._('Usage') }}</a></li>
        <li><a data-toggle="tab" href="#services">{{ lang._('Services') }}</a></li>
        <li><a data-toggle="tab" href="#rules">{{ lang._('Advanced rules') }}</a></li>
        <li><a data-toggle="tab" href="#activity">{{ lang._('Activity') }}</a></li>
        <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
    </ul>

    <div class="tab-content">
        <div id="usage" class="tab-pane fade in active">
            <div class="l7-toolbar">
                <select id="ai-period" class="form-control" style="width:auto">
                    <option value="3600">{{ lang._('Last hour') }}</option>
                    <option value="86400" selected="selected">{{ lang._('Last 24 hours') }}</option>
                    <option value="604800">{{ lang._('Last 7 days') }}</option>
                </select>
                <button class="btn btn-default" id="aiRefresh" type="button"><span class="fa fa-refresh"></span> {{ lang._('Refresh') }}</button>
            </div>
            <div class="l7-grid2">
                <div class="l7-card"><h3>{{ lang._('AI services in use') }}</h3>
                    <table class="l7-table" id="tbl-ai-services"><thead><tr><th>{{ lang._('Service') }}</th><th class="num">{{ lang._('Devices') }}</th><th class="num">{{ lang._('Connections') }}</th><th class="num">{{ lang._('Down') }}</th><th class="num">{{ lang._('Up') }}</th><th class="num">{{ lang._('Blocked') }}</th></tr></thead><tbody></tbody></table></div>
                <div class="l7-card"><h3>{{ lang._('Who uses what') }}</h3>
                    <table class="l7-table" id="tbl-ai-clients"><thead><tr><th>{{ lang._('Device') }}</th><th>{{ lang._('Service') }}</th><th class="num">{{ lang._('Volume') }}</th><th>{{ lang._('Result') }}</th><th>{{ lang._('Last seen') }}</th></tr></thead><tbody></tbody></table></div>
            </div>
        </div>

        <div id="services" class="tab-pane fade">
            <div class="l7-hint">
                {{ lang._('Pick what happens to each AI service for everybody. "Default" follows the setting in the Settings tab. Tick "Check content" to look for card numbers, passwords and source code in what people send (needs AI Inspection and DPI-SSL).') }}
            </div>
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-svc">
                    <thead><tr><th>{{ lang._('Service') }}</th><th>{{ lang._('Websites') }}</th><th style="width:34em">{{ lang._('What to do') }}</th><th>{{ lang._('Check content') }}</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
            <button class="btn btn-primary" id="svc-save" type="button" style="margin-top:12px"><i class="fa fa-save"></i> {{ lang._('Save') }}</button>
        </div>

        <div id="rules" class="tab-pane fade">
            <div class="l7-hint">{{ lang._('Rules for certain devices, users or hours. The first rule that matches decides; services without a rule follow the default.') }}</div>
            <table id="grid-ai" class="table table-condensed table-hover table-striped" data-editDialog="DialogAi" data-editAlert="l7-pending">
                <thead>
                    <tr>
                        <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                        <th data-column-id="enabled" data-width="5em" data-type="string" data-formatter="rowtoggle">{{ lang._('On') }}</th>
                        <th data-column-id="service" data-type="string">{{ lang._('Service') }}</th>
                        <th data-column-id="action" data-width="7em" data-type="string">{{ lang._('Action') }}</th>
                        <th data-column-id="inspect" data-width="6em" data-type="boolean" data-formatter="boolean">{{ lang._('Check') }}</th>
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
                        <td colspan="9">
                            <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-fw fa-plus"></span> {{ lang._('Add rule') }}</button>
                            <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-fw fa-trash-o"></span></button>
                        </td>
                    </tr>
                </tfoot>
            </table>
        </div>

        <div id="activity" class="tab-pane fade">
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-ailog">
                    <thead><tr><th>{{ lang._('Time') }}</th><th>{{ lang._('Device') }}</th><th>{{ lang._('Service') }}</th><th>{{ lang._('Result') }}</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>

        <div id="settings" class="tab-pane fade">
            {{ partial("layout_partials/base_form", ['fields': aiForm, 'id': 'frm_ai']) }}
            <button class="btn btn-primary" id="ai-save" type="button"><i class="fa fa-save"></i> {{ lang._('Save') }}</button>
        </div>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogAi, 'id': 'DialogAi', 'label': lang._('AI service rule')]) }}

<script>
$(document).ready(function () {
    var E = L7.esc, SVC = [], EDIT = {}, STATE = {};
    L7.applyButton('#reconfigureAct', function () { loadState(); loadUsage(); }, ['frm_ai']);
    L7.rememberTabs('ai');
    L7.engineStatus('#l7-engine-pill');

    mapDataToFormUI({'frm_ai': '/api/layer7security/settings/get'}).done(function () { $('.selectpicker').selectpicker('refresh'); });
    $('#ai-save').on('click', function () {
        saveFormToEndpoint('/api/layer7security/settings/set', 'frm_ai', function () { L7.pending(); L7.toast('{{ lang._('Saved. Click Apply changes to activate.') }}'); loadState(); });
    });

    $('#grid-ai').UIBootgrid({
        search: '/api/layer7security/settings/search_ai',
        get: '/api/layer7security/settings/get_ai/',
        set: '/api/layer7security/settings/set_ai/',
        add: '/api/layer7security/settings/add_ai/',
        del: '/api/layer7security/settings/del_ai/',
        toggle: '/api/layer7security/settings/toggle_ai/'
    });

    function loadUsage() {
        L7.get('/api/layer7security/dashboard/ai', {period: $('#ai-period').val()}).done(function (d) {
            if (!d || !d.services) { return; }
            $('#tbl-ai-services tbody').html(d.services.map(function (r) {
                return '<tr><td><strong>' + E(r.name) + '</strong></td><td class="num">' + L7.num(r.clients) + '</td><td class="num">' + L7.num(r.flows) + '</td><td class="num">' + L7.bytes(r.down) + '</td><td class="num">' + L7.bytes(r.up) + '</td><td class="num">' + (r.blocked > 0 ? L7.tag(r.blocked, 'block') : '0') + '</td></tr>';
            }).join('') || '<tr><td colspan="6">' + L7.empty('microchip', '{{ lang._('No AI traffic seen in this period.') }}') + '</td></tr>');
            $('#tbl-ai-clients tbody').html((d.clients || []).map(function (r) {
                return '<tr><td class="mono">' + E(r.client) + '</td><td>' + E(r.name) + '</td><td class="num">' + L7.bytes(r.down + r.up) + '</td><td>' + (r.blocked > 0 ? L7.tag('{{ lang._('blocked') }}', 'block') : L7.tag('{{ lang._('seen') }}', '')) + '</td><td>' + E(L7.ago(r.last)) + '</td></tr>';
            }).join('') || '<tr><td colspan="5">' + L7.empty('user', '-') + '</td></tr>');
            var used = d.services.length, blocked = d.services.reduce(function (a, r) { return a + (r.blocked || 0); }, 0);
            STATE.used = used; STATE.blocked = blocked; tiles();
        });
    }

    function tiles() {
        $('#l7-module-pill').replaceWith($(STATE.enabled ? L7.pill('{{ lang._('AI control on') }}', 'ok') : L7.pill('{{ lang._('AI control off') }}', 'warn')).attr('id', 'l7-module-pill'));
        var blk = SVC.filter(function (s) { return (s.action || STATE.def) === 'block'; }).length;
        var mon = SVC.filter(function (s) { return (s.action || STATE.def) === 'monitor'; }).length;
        $('#ai-tiles').html(
            L7.tile(STATE.enabled ? '{{ lang._('On') }}' : '{{ lang._('Off') }}', '{{ lang._('AI control') }}', '', STATE.enabled ? 'ok' : 'warn') +
            L7.tile(SVC.length, '{{ lang._('Services known') }}') +
            L7.tile(blk, '{{ lang._('Blocked') }}', '', blk ? 'bad' : '') +
            L7.tile(mon, '{{ lang._('Watched') }}') +
            L7.tile(STATE.used || 0, '{{ lang._('In use now') }}') +
            L7.tile(L7.num(STATE.blocked || 0), '{{ lang._('Blocked connections') }}', '', STATE.blocked ? 'warn' : '')
        );
    }

    function radio(id, v, current, label) {
        return '<label style="margin-right:10px;font-weight:normal;cursor:pointer"><input type="radio" class="svc-act" name="svc-' + E(id) + '" data-id="' + E(id) + '" value="' + v + '"' + (current === v ? ' checked' : '') + '> ' + label + '</label>';
    }

    function loadState() {
        L7.get('/api/layer7security/ai/state').done(function (d) {
            SVC = d.services || []; STATE.def = d.default; STATE.enabled = d.enabled; EDIT = {};
            $('#tbl-svc tbody').html(SVC.map(function (s) {
                var a = s.action || '';
                return '<tr><td><strong>' + E(s.name) + '</strong></td><td class="l7-muted trunc" title="' + E((s.domains || []).join(', ')) + '">' + E((s.domains || []).slice(0, 2).join(', ')) + '</td><td style="white-space:nowrap">' +
                    radio(s.id, '', a, '{{ lang._('Default') }} (' + E(d.default) + ')') + radio(s.id, 'allow', a, '{{ lang._('Allow') }}') + radio(s.id, 'monitor', a, '{{ lang._('Watch') }}') +
                    radio(s.id, 'block', a, '<span style="color:var(--l7-bad)">{{ lang._('Block') }}</span>') +
                    '</td><td><input type="checkbox" class="svc-insp" data-id="' + E(s.id) + '"' + (s.inspect ? ' checked' : '') + '></td></tr>';
            }).join(''));
            tiles();
        });
    }
    function find(id) { return SVC.filter(function (s) { return s.id === id; })[0] || {}; }
    function edit(id) { return EDIT[id] || (EDIT[id] = {action: find(id).action || '', inspect: !!find(id).inspect}); }
    $('#services').on('change', '.svc-act', function () { edit($(this).data('id')).action = $(this).val(); });
    $('#services').on('change', '.svc-insp', function () { edit($(this).data('id')).inspect = $(this).is(':checked'); });
    $('#svc-save').on('click', function () {
        if (!Object.keys(EDIT).length) { L7.toast('{{ lang._('Nothing was changed.') }}', 'warn'); return; }
        var body = {};
        Object.keys(EDIT).forEach(function (k) {
            // "Check content" needs a rule: keep the default action as an explicit rule when only that was ticked
            var e = EDIT[k];
            body[k] = {action: e.action || (e.inspect ? (STATE.def === 'block' ? 'monitor' : STATE.def) : ''), inspect: e.inspect};
        });
        L7.post('/api/layer7security/ai/save', {services: JSON.stringify(body)}).done(function (r) {
            if (r && r.result === 'saved') { L7.pending(); L7.toast('{{ lang._('Saved. Click Apply changes to activate.') }}'); loadState(); }
            else { L7.toast('{{ lang._('Could not save.') }}', 'bad'); }
        });
    });

    function loadLog() {
        L7.get('/api/layer7security/live/events', {module: 'ai', minutes: 1440, limit: 200}).done(function (d) {
            $('#tbl-ailog tbody').html(((d && d.rows) || []).map(function (r) {
                return '<tr><td title="' + E(L7.when(r.ts)) + '">' + E(L7.ago(r.ts)) + '</td><td class="mono">' + E(r.client) + '</td><td>' + E(r.app || r.host) + '</td><td>' + (r.type === 'ai-block' ? L7.tag('{{ lang._('blocked') }}', 'block') : L7.tag('{{ lang._('seen') }}', '')) + '</td></tr>';
            }).join('') || '<tr><td colspan="4">' + L7.empty('microchip', '{{ lang._('No AI activity yet.') }}') + '</td></tr>');
        });
    }
    $('a[href="#activity"]').on('shown.bs.tab', loadLog);
    $('#ai-period').on('change', loadUsage);
    $('#aiRefresh').on('click', loadUsage);
    loadState();
    loadUsage();
});
</script>
