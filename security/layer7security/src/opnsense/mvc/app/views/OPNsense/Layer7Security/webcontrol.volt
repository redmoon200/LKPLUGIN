<div class="l7">
    {{ partial('OPNsense/Layer7Security/partials/header', [
        'title': lang._('Web Control'),
        'subtitle': lang._('Block or allow websites and IP addresses. Wildcards such as *instagram.com cover a whole site including every sub-domain.'),
        'icon': 'globe',
        'accent': 'prot',
        'apply': true
    ]) }}

    <div class="l7-tiles" id="wc-tiles"></div>

    <ul class="nav nav-tabs" role="tablist">
        <li class="active"><a data-toggle="tab" href="#tab-rules">{{ lang._('Rules') }}</a></li>
        <li><a data-toggle="tab" href="#tab-test">{{ lang._('Test a website') }}</a></li>
        <li><a data-toggle="tab" href="#tab-activity">{{ lang._('Activity') }}</a></li>
        <li><a data-toggle="tab" href="#tab-settings">{{ lang._('Settings') }}</a></li>
    </ul>

    <div class="tab-content">
        <div id="tab-rules" class="tab-pane fade in active">
            <div class="l7-toolbar">
                <span class="l7-chip on" data-show="all">{{ lang._('All') }}</span>
                <span class="l7-chip" data-show="domain">{{ lang._('Websites') }}</span>
                <span class="l7-chip" data-show="ip">{{ lang._('IP addresses') }}</span>
                <span class="l7-chip" data-show="temporary">{{ lang._('Temporary') }}</span>
                <span style="flex:1"></span>
                <button class="btn btn-primary" id="wc-add-quick" type="button"><i class="fa fa-plus"></i> {{ lang._('Add rule') }}</button>
                <button class="btn btn-default" id="wc-bulk" type="button"><i class="fa fa-list"></i> {{ lang._('Add many at once') }}</button>
            </div>
            <table id="grid-rules" class="table table-condensed table-hover table-striped" data-editDialog="DialogWebRule" data-editAlert="l7-pending">
                <thead>
                    <tr>
                        <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                        <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle">{{ lang._('On') }}</th>
                        <th data-column-id="kind" data-width="8em" data-formatter="kind">{{ lang._('Type') }}</th>
                        <th data-column-id="value" data-type="string">{{ lang._('Website or IP address') }}</th>
                        <th data-column-id="action" data-width="7em" data-formatter="act">{{ lang._('Action') }}</th>
                        <th data-column-id="sources" data-type="string" data-formatter="who">{{ lang._('Applies to') }}</th>
                        <th data-column-id="expires" data-width="9em" data-formatter="ends">{{ lang._('Ends') }}</th>
                        <th data-column-id="description" data-type="string">{{ lang._('Note') }}</th>
                        <th data-column-id="commands" data-width="9em" data-formatter="commands" data-sortable="false">{{ lang._('Edit') }}</th>
                    </tr>
                </thead>
                <tbody></tbody>
                <tfoot>
                    <tr>
                        <td></td>
                        <td colspan="8">
                            <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-fw fa-plus"></span> {{ lang._('Add rule') }}</button>
                            <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-fw fa-trash-o"></span> {{ lang._('Delete selected') }}</button>
                        </td>
                    </tr>
                </tfoot>
            </table>
        </div>

        <div id="tab-test" class="tab-pane fade">
            <div class="l7-card">
                <h3>{{ lang._('What happens to this website?') }}</h3>
                <p class="l7-muted">{{ lang._('Type a website or an IP address to see which rules apply to it.') }}</p>
                <div class="l7-toolbar">
                    <input type="text" id="wc-test-q" class="form-control grow" placeholder="www.instagram.com" maxlength="120"/>
                    <button class="btn btn-primary" id="wc-test-go" type="button"><i class="fa fa-search"></i> {{ lang._('Check') }}</button>
                </div>
                <div id="wc-test-out"></div>
            </div>
        </div>

        <div id="tab-activity" class="tab-pane fade">
            <div class="l7-scroll">
                <table class="l7-table" id="wc-log">
                    <thead><tr><th>{{ lang._('Time') }}</th><th>{{ lang._('Device') }}</th><th>{{ lang._('Website or address') }}</th><th>{{ lang._('Rule') }}</th><th>{{ lang._('Action') }}</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>

        <div id="tab-settings" class="tab-pane fade">
            <div class="l7-card">
                {{ partial("layout_partials/base_form", ['fields': webForm, 'id': 'frm_web']) }}
                <button class="btn btn-primary" id="wc-save" type="button"><i class="fa fa-save"></i> {{ lang._('Save') }}</button>
            </div>
        </div>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogWebRule, 'id': 'DialogWebRule', 'label': lang._('Web Control rule')]) }}

<script>
$(document).ready(function () {
    var E = L7.esc, SHOW = 'all', LOG = [];
    L7.applyButton('#reconfigureAct', loadStatus, ['frm_web']);
    L7.rememberTabs('web');
    L7.engineStatus('#l7-engine-pill');

    mapDataToFormUI({'frm_web': '/api/layer7security/settings/get'}).done(function () { $('.selectpicker').selectpicker('refresh'); });
    $('#wc-save').on('click', function () {
        saveFormToEndpoint('/api/layer7security/settings/set', 'frm_web', function () { L7.pending(); loadStatus(); L7.toast('{{ lang._('Saved. Click Apply changes to activate.') }}'); });
    });

    function ends(row) {
        var e = parseInt(row.expires, 10) || 0;
        if (!e) { return '<span class="l7-muted">{{ lang._('never') }}</span>'; }
        var left = e - Math.floor(Date.now() / 1000);
        return left > 0 ? E('{{ lang._('in') }} ' + L7.dur(left)) : '<span class="l7-muted">{{ lang._('ended') }}</span>';
    }

    $('#grid-rules').UIBootgrid({
        search: '/api/layer7security/webcontrol/searchRule',
        get: '/api/layer7security/webcontrol/getRule/',
        set: '/api/layer7security/webcontrol/setRule/',
        add: '/api/layer7security/webcontrol/addRule/',
        del: '/api/layer7security/webcontrol/delRule/',
        toggle: '/api/layer7security/webcontrol/toggleRule/',
        options: {
            rowCount: [25, 50, 100],
            requestHandler: function (request) {
                if (SHOW === 'domain' || SHOW === 'ip') { request.kind = SHOW; }
                if (SHOW === 'temporary') { request.only = 'temporary'; }
                return request;
            },
            formatters: {
                kind: function (c, row) { return E(row.kind === 'ip' ? '{{ lang._('IP address') }}' : '{{ lang._('Website') }}'); },
                act: function (c, row) { return L7.tag(row.action === 'allow' ? '{{ lang._('Allow') }}' : '{{ lang._('Block') }}', row.action); },
                who: function (c, row) { return row.sources ? E(row.sources) : '<span class="l7-muted">{{ lang._('everyone') }}</span>'; },
                ends: function (c, row) {
                    var h = ends(row);
                    if ((parseInt(row.expires, 10) || 0) > 0) {
                        h += ' <button class="btn btn-xs btn-default wc-perm" data-uuid="' + E(row.uuid) + '" title="{{ lang._('Keep this rule for good') }}"><i class="fa fa-thumb-tack"></i></button>';
                    }
                    return h;
                }
            }
        }
    }).on('loaded.rs.jquery.bootgrid', function () {
        $('#grid-rules .wc-perm').off('click').on('click', function () {
            L7.post('/api/layer7security/webcontrol/permanent/' + $(this).data('uuid')).done(function () { $('#grid-rules').bootgrid('reload'); L7.toast('{{ lang._('The rule is now permanent.') }}'); });
        });
    });

    $('.l7-chip[data-show]').on('click', function () {
        SHOW = $(this).data('show');
        $('.l7-chip[data-show]').removeClass('on');
        $(this).addClass('on');
        $('#grid-rules').bootgrid('reload');
    });

    $('#wc-add-quick').on('click', function () { $('button.command-add').first().trigger('click'); });

    $('#wc-bulk').on('click', function () {
        var body = '<div class="l7"><p class="l7-muted">{{ lang._('Paste websites or IP addresses, one per line or separated by commas. Wildcards work (*.example.com).') }}</p>' +
            '<textarea id="bulk-text" class="form-control" rows="9" placeholder="*.example.com&#10;ads.example.net&#10;203.0.113.0/24"></textarea>' +
            '<div class="form-group" style="margin-top:10px"><label>{{ lang._('What to do') }}</label><select id="bulk-action" class="form-control"><option value="block">{{ lang._('Block') }}</option><option value="allow">{{ lang._('Allow') }}</option></select></div></div>';
        BootstrapDialog.show({title: '{{ lang._('Add many at once') }}', message: body, buttons: [
            {label: '{{ lang._('Cancel') }}', action: function (d) { d.close(); }},
            {id: 'bulk-go', label: '{{ lang._('Add') }}', cssClass: 'btn-primary', action: function (d) {
                L7.post('/api/layer7security/webcontrol/bulk', {text: $('#bulk-text').val(), action: $('#bulk-action').val()}).done(function (r) {
                    d.close();
                    if (r && r.result === 'saved') {
                        var m = r.added + ' {{ lang._('added') }}' + (r.skipped ? ', ' + r.skipped + ' {{ lang._('already there') }}' : '') + (r.invalid && r.invalid.length ? ', ' + r.invalid.length + ' {{ lang._('not understood') }}: ' + r.invalid.slice(0, 3).join(' ') : '');
                        L7.toast(m, r.invalid && r.invalid.length ? 'warn' : '');
                        if (r.added) { L7.pending(); }
                        $('#grid-rules').bootgrid('reload'); loadStatus();
                    } else { L7.toast((r && r.message) || '{{ lang._('Could not save.') }}', 'bad'); }
                });
            }}]});
    });

    /* ---- tiles ---- */
    function loadStatus() {
        L7.get('/api/layer7security/webcontrol/status').done(function (d) {
            if (!d || !d.rules) { return; }
            var on = d.enabled;
            $('#l7-module-pill').replaceWith($(L7.pill(on ? '{{ lang._('Web Control on') }}' : '{{ lang._('Web Control off') }}', on ? 'ok' : 'warn')).attr('id', 'l7-module-pill'));
            $('#wc-tiles').html(
                L7.tile(d.total, '{{ lang._('Active rules') }}') +
                L7.tile(d.rules.block, '{{ lang._('Block rules') }}', '', d.rules.block ? 'bad' : '') +
                L7.tile(d.rules.allow, '{{ lang._('Allow rules') }}', '', d.rules.allow ? 'ok' : '') +
                L7.tile(d.rules.domain, '{{ lang._('Websites') }}') +
                L7.tile(d.rules.ip, '{{ lang._('IP addresses') }}') +
                L7.tile(d.rules.temporary, '{{ lang._('Temporary') }}') +
                L7.tile(L7.num(LOG.length), '{{ lang._('Blocked in 24 h') }}', '', LOG.length ? 'warn' : '')
            );
        });
    }

    function loadLog() {
        L7.get('/api/layer7security/live/events', {module: 'web', minutes: 1440, limit: 200}).done(function (d) {
            LOG = (d && d.rows) || [];
            $('#wc-log tbody').html(LOG.map(function (r, i) {
                return '<tr><td title="' + E(L7.when(r.ts)) + '">' + E(L7.ago(r.ts)) + '</td><td class="mono">' + E(r.client) + '</td><td class="trunc">' + E(r.host || r.server) + '</td>' +
                    '<td>' + E(r.policy) + '</td><td><button class="btn btn-xs btn-success wc-allow" data-i="' + i + '"><i class="fa fa-check"></i> {{ lang._('Allow') }}</button></td></tr>';
            }).join('') || '<tr><td colspan="5">' + L7.empty('check-circle', '{{ lang._('Nothing was blocked yet.') }}') + '</td></tr>');
            loadStatus();
        });
    }
    $('#wc-log').on('click', '.wc-allow', function () {
        var r = LOG[$(this).data('i')];
        var host = r.host || r.server;
        L7.confirm({title: '{{ lang._('Allow this?') }}', message: E('{{ lang._('Always allow') }} ' + host + '?'), yes: '{{ lang._('Allow') }}', onYes: function () {
            L7.post('/api/layer7security/webcontrol/quick', {kind: r.host ? 'domain' : 'ip', value: host, action: 'allow', minutes: 0, note: 'from activity'}).done(function (res) {
                L7.toast(res && res.result === 'saved' ? '{{ lang._('Allowed and active.') }}' : ((res && res.message) || '{{ lang._('Failed') }}'), res && res.result === 'saved' ? '' : 'bad');
                $('#grid-rules').bootgrid('reload');
            });
        }});
    });

    /* ---- test box ---- */
    function runTest() {
        var q = $('#wc-test-q').val();
        if (!q) { return; }
        L7.post('/api/layer7security/webcontrol/test', {q: q}).done(function (d) {
            var v = d.verdict, h = '';
            if (!d.query) { h = '<div class="l7-hint warn">{{ lang._('That does not look like a website or an IP address.') }}</div>'; }
            else if (v === 'block') { h = '<div class="l7-hint bad"><strong>' + E(d.query) + '</strong> {{ lang._('is blocked by Web Control.') }}</div>'; }
            else if (v === 'allow') { h = '<div class="l7-hint ok"><strong>' + E(d.query) + '</strong> {{ lang._('is always allowed by Web Control.') }}</div>'; }
            else { h = '<div class="l7-hint"><strong>' + E(d.query) + '</strong> {{ lang._('has no Web Control rule. Content filtering and other protection can still apply.') }}</div>'; }
            if (d.matches && d.matches.length) {
                h += '<table class="l7-table"><thead><tr><th>{{ lang._('Matching rule') }}</th><th>{{ lang._('Action') }}</th><th>{{ lang._('Applies to') }}</th></tr></thead><tbody>' +
                    d.matches.map(function (m) { return '<tr><td class="mono">' + E(m.value) + '</td><td>' + L7.tag(m.action, m.action) + '</td><td>' + (m.sources.length ? E(m.sources.join(', ')) : '{{ lang._('everyone') }}') + '</td></tr>'; }).join('') + '</tbody></table>';
            }
            $('#wc-test-out').html(h);
        });
    }
    $('#wc-test-go').on('click', runTest);
    $('#wc-test-q').on('keydown', function (e) { if (e.which === 13) { runTest(); } });

    loadStatus();
    loadLog();
    $('a[href="#tab-activity"]').on('shown.bs.tab', loadLog);
});
</script>
