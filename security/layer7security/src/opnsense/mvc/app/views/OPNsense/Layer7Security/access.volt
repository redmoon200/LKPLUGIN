<div class="l7">
    {{ partial('OPNsense/Layer7Security/partials/header', [
        'title': lang._('Users and Access'),
        'subtitle': lang._('Decide who may use the web, by device address or by signing in with a user name and password.'),
        'icon': 'users',
        'accent': 'con',
        'apply': true
    ]) }}

    <div class="l7-tiles" id="ac-tiles"></div>

    <ul class="nav nav-tabs" role="tablist">
        <li class="active"><a data-toggle="tab" href="#tab-signed">{{ lang._('Signed-in users') }}</a></li>
        <li><a data-toggle="tab" href="#tab-settings">{{ lang._('Sign-in settings') }}</a></li>
        <li><a data-toggle="tab" href="#tab-users">{{ lang._('Named users and devices') }}</a></li>
        <li><a data-toggle="tab" href="#tab-log">{{ lang._('Sign-in log') }}</a></li>
    </ul>

    <div class="tab-content">
        <div id="tab-signed" class="tab-pane fade in active">
            <div id="ac-state"></div>
            <div class="l7-toolbar">
                <button class="btn btn-default" id="ac-refresh" type="button"><i class="fa fa-refresh"></i> {{ lang._('Refresh') }}</button>
                <button class="btn btn-danger" id="ac-logout-all" type="button"><i class="fa fa-sign-out"></i> {{ lang._('Sign everybody out') }}</button>
            </div>
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-sessions">
                    <thead>
                        <tr><th>{{ lang._('User') }}</th><th>{{ lang._('Device address') }}</th><th>{{ lang._('MAC address') }}</th><th>{{ lang._('Signed in') }}</th><th>{{ lang._('Last activity') }}</th><th>{{ lang._('Ends') }}</th><th></th></tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>

        <div id="tab-settings" class="tab-pane fade">
            <div class="l7-hint warn">
                {{ lang._('Make sure your own computer is in "Never ask these devices" before you turn this on. The firewall web interface itself stays reachable.') }}
            </div>
            {{ partial("layout_partials/base_form", ['fields': authForm, 'id': 'frm_auth']) }}
            <button class="btn btn-primary" id="ac-save" type="button"><i class="fa fa-save"></i> {{ lang._('Save') }}</button>
        </div>

        <div id="tab-users" class="tab-pane fade">
            <table id="grid-users" class="table table-condensed table-hover table-striped" data-editDialog="DialogUser" data-editAlert="l7-pending">
                <thead>
                    <tr>
                        <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                        <th data-column-id="name" data-type="string">{{ lang._('Name') }}</th>
                        <th data-column-id="addresses" data-type="string">{{ lang._('IP addresses') }}</th>
                        <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
                        <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">{{ lang._('Edit') }}</th>
                    </tr>
                </thead>
                <tbody></tbody>
                <tfoot>
                    <tr>
                        <td></td>
                        <td colspan="4">
                            <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-fw fa-plus"></span> {{ lang._('Add user') }}</button>
                            <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-fw fa-trash-o"></span></button>
                        </td>
                    </tr>
                </tfoot>
            </table>
        </div>

        <div id="tab-log" class="tab-pane fade">
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-authlog">
                    <thead><tr><th>{{ lang._('Time') }}</th><th>{{ lang._('Event') }}</th><th>{{ lang._('User') }}</th><th>{{ lang._('Device address') }}</th><th>{{ lang._('Details') }}</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogUser, 'id': 'DialogUser', 'label': lang._('Named user')]) }}

<script>
$(document).ready(function () {
    var E = L7.esc;
    L7.applyButton('#reconfigureAct', loadAll, ['frm_auth']);
    L7.rememberTabs('access');
    L7.engineStatus('#l7-engine-pill');

    mapDataToFormUI({'frm_auth': '/api/layer7security/settings/get'}).done(function () { $('.selectpicker').selectpicker('refresh'); });
    $('#ac-save').on('click', function () {
        saveFormToEndpoint('/api/layer7security/settings/set', 'frm_auth', function () {
            L7.pending();
            L7.toast('{{ lang._('Saved. Click Apply changes to activate.') }}');
        });
    });

    $('#grid-users').UIBootgrid({
        search: '/api/layer7security/settings/search_user',
        get: '/api/layer7security/settings/get_user/',
        set: '/api/layer7security/settings/set_user/',
        add: '/api/layer7security/settings/add_user/',
        del: '/api/layer7security/settings/del_user/'
    });

    function loadStatus() {
        L7.get('/api/layer7security/access/status').done(function (d) {
            var pill;
            if (!d.configured) { pill = L7.pill('{{ lang._('Sign-in off') }}', 'plain'); }
            else if (d.running && d.ready) { pill = L7.pill('{{ lang._('Sign-in on') }}', 'ok'); }
            else { pill = L7.pill('{{ lang._('Sign-in not running') }}', 'bad'); }
            $('#l7-module-pill').replaceWith($(pill).attr('id', 'l7-module-pill'));
            $('#ac-tiles').html(
                L7.tile(L7.num(d.active || 0), '{{ lang._('Signed in now') }}', '', d.active ? 'ok' : '') +
                L7.tile(L7.num(d.logins24h || 0), '{{ lang._('Sign-ins in 24 h') }}') +
                L7.tile(L7.num(d.failures24h || 0), '{{ lang._('Failed in 24 h') }}', '', d.failures24h ? 'warn' : '') +
                L7.tile(L7.num(d.expired24h || 0), '{{ lang._('Timed out in 24 h') }}')
            );
            var msg = '';
            if (!d.configured) {
                msg = '<div class="l7-hint">{{ lang._('Sign-in is switched off. Turn it on under "Sign-in settings".') }}</div>';
            } else if (!d.running || !d.ready) {
                msg = '<div class="l7-hint bad">{{ lang._('Sign-in is switched on but the login page is not running. Click Apply changes. Devices are not being asked to sign in.') }}</div>';
            }
            $('#ac-state').html(msg);
        });
    }

    function loadSessions() {
        L7.get('/api/layer7security/access/sessions').done(function (d) {
            var rows = (d && d.rows) || [];
            $('#tbl-sessions tbody').html(rows.map(function (r) {
                return '<tr><td><strong>' + E(r.user) + '</strong></td><td class="mono">' + E(r.ip) + '</td><td class="mono">' + E(r.mac) + '</td>' +
                    '<td title="' + E(L7.when(r.started)) + '">' + E(L7.ago(r.started)) + '</td><td>' + E(L7.ago(r.last_active)) + '</td>' +
                    '<td>' + E('{{ lang._('in') }} ' + L7.dur(r.expires - Math.floor(Date.now() / 1000))) + '</td>' +
                    '<td><button class="btn btn-xs btn-default ac-out" data-ip="' + E(r.ip) + '"><i class="fa fa-sign-out"></i> {{ lang._('Sign out') }}</button></td></tr>';
            }).join('') || '<tr><td colspan="7">' + L7.empty('user', '{{ lang._('Nobody is signed in.') }}') + '</td></tr>');
        });
    }

    var NAMES = {login: '{{ lang._('Signed in') }}', fail: '{{ lang._('Wrong password') }}', lockout: '{{ lang._('Locked for 5 minutes') }}',
                 logout: '{{ lang._('Signed out') }}', 'admin-logout': '{{ lang._('Signed out by admin') }}', expire: '{{ lang._('Session ended') }}'};
    function loadLog() {
        L7.get('/api/layer7security/access/log', {rows: 200}).done(function (d) {
            var rows = (d && d.rows) || [];
            $('#tbl-authlog tbody').html(rows.map(function (r) {
                var bad = r.type === 'fail' || r.type === 'lockout';
                return '<tr><td title="' + E(L7.when(r.ts)) + '">' + E(L7.ago(r.ts)) + '</td><td>' + L7.tag(NAMES[r.type] || r.type, bad ? 'block' : (r.type === 'login' ? 'allow' : '')) + '</td>' +
                    '<td>' + E(r.user) + '</td><td class="mono">' + E(r.ip) + '</td><td>' + E(r.detail) + '</td></tr>';
            }).join('') || '<tr><td colspan="5">' + L7.empty('list', '{{ lang._('No sign-in events yet.') }}') + '</td></tr>');
        });
    }

    function loadAll() { loadStatus(); loadSessions(); loadLog(); }

    $('#tbl-sessions').on('click', '.ac-out', function () {
        var ip = $(this).data('ip');
        L7.confirm({title: '{{ lang._('Sign out?') }}', message: E('{{ lang._('Sign out the device') }} ' + ip + '?'), yes: '{{ lang._('Sign out') }}', danger: true, onYes: function () {
            L7.post('/api/layer7security/access/logout', {ip: ip}).done(function () { loadAll(); L7.toast('{{ lang._('Signed out.') }}'); });
        }});
    });
    $('#ac-logout-all').on('click', function () {
        L7.confirm({title: '{{ lang._('Sign everybody out?') }}', message: '{{ lang._('Every device has to sign in again.') }}', yes: '{{ lang._('Sign everybody out') }}', danger: true, onYes: function () {
            L7.post('/api/layer7security/access/logoutAll').done(function () { loadAll(); L7.toast('{{ lang._('Everybody is signed out.') }}'); });
        }});
    });
    $('#ac-refresh').on('click', loadAll);
    $('a[href="#tab-log"]').on('shown.bs.tab', loadLog);
    loadAll();
    setInterval(function () { if ($('#tab-signed').hasClass('active')) { loadStatus(); loadSessions(); } }, 10000);
});
</script>
