<div class="l7">
    {{ partial('OPNsense/Layer7Security/partials/header', [
        'title': lang._('Application Control'),
        'subtitle': lang._('Allow, watch or block applications such as YouTube, TikTok, BitTorrent or VPN services, whatever website name or port they use.'),
        'icon': 'th-large',
        'accent': 'prot',
        'apply': true
    ]) }}

    <div class="l7-tiles" id="app-tiles"></div>

    <ul class="nav nav-tabs" role="tablist">
        <li class="active"><a data-toggle="tab" href="#tab-cats">{{ lang._('Categories') }}</a></li>
        <li><a data-toggle="tab" href="#tab-apps">{{ lang._('Applications') }}</a></li>
        <li><a data-toggle="tab" href="#tab-rules">{{ lang._('Advanced rules') }}</a></li>
        <li><a data-toggle="tab" href="#tab-activity">{{ lang._('Activity') }}</a></li>
    </ul>

    <div class="tab-content">
        <div id="tab-cats" class="tab-pane fade in active">
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-appcats">
                    <thead><tr><th>{{ lang._('Category') }}</th><th>{{ lang._('Examples') }}</th><th style="width:19em">{{ lang._('What to do') }}</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
            <button class="btn btn-primary" id="cats-save" type="button" style="margin-top:12px"><i class="fa fa-save"></i> {{ lang._('Save') }}</button>
        </div>

        <div id="tab-apps" class="tab-pane fade">
            <div class="l7-toolbar">
                <input type="text" id="app-q" class="form-control grow" placeholder="{{ lang._('Search, for example youtube or tiktok') }}" maxlength="40"/>
                <span class="l7-muted" id="app-total"></span>
            </div>
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-apps">
                    <thead><tr><th>{{ lang._('Application') }}</th><th>{{ lang._('Category') }}</th><th style="width:19em">{{ lang._('What to do') }}</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
            <button class="btn btn-primary" id="apps-save" type="button" style="margin-top:12px"><i class="fa fa-save"></i> {{ lang._('Save') }}</button>
        </div>

        <div id="tab-rules" class="tab-pane fade">
            <table id="grid-policies" class="table table-condensed table-hover table-striped" data-editDialog="DialogPolicy" data-editAlert="l7-pending">
                <thead>
                    <tr>
                        <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                        <th data-column-id="enabled" data-width="5em" data-type="string" data-formatter="rowtoggle">{{ lang._('On') }}</th>
                        <th data-column-id="sequence" data-width="5em" data-type="numeric">{{ lang._('Order') }}</th>
                        <th data-column-id="name" data-type="string">{{ lang._('Name') }}</th>
                        <th data-column-id="action" data-width="6em" data-formatter="act">{{ lang._('Action') }}</th>
                        <th data-column-id="applications" data-type="string">{{ lang._('Applications') }}</th>
                        <th data-column-id="categories" data-type="string">{{ lang._('Categories') }}</th>
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
                        <td colspan="12">
                            <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-fw fa-plus"></span> {{ lang._('Add rule') }}</button>
                            <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-fw fa-trash-o"></span></button>
                        </td>
                    </tr>
                </tfoot>
            </table>
        </div>

        <div id="tab-activity" class="tab-pane fade">
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-applog">
                    <thead><tr><th>{{ lang._('Time') }}</th><th>{{ lang._('Device') }}</th><th>{{ lang._('Application') }}</th><th>{{ lang._('Website or address') }}</th><th>{{ lang._('Rule') }}</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>

    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogPolicy, 'id': 'DialogPolicy', 'label': lang._('Application rule')]) }}

<script>
$(document).ready(function () {
    var E = L7.esc, STATE = {categories: {}, applications: {}}, EDIT = {categories: {}, applications: {}}, QUICK = [], LOG = [];
    var EXAMPLES = {SocialNetwork: 'Facebook, Instagram, TikTok, X', Streaming: 'Netflix, Twitch, Disney+', Video: 'YouTube, Vimeo', Music: 'Spotify, Apple Music',
        Game: 'Steam, Fortnite, Roblox', Chat: 'WhatsApp, Telegram, Discord', VoIP: 'Zoom, Skype, Teams calls', VPN: 'OpenVPN, WireGuard, NordVPN, Tor',
        RemoteAccess: 'TeamViewer, AnyDesk, RDP, SSH', FileSharing: 'BitTorrent, eMule', Download: 'FTP, download managers', Cloud: 'Dropbox, Google Drive, OneDrive',
        Shopping: 'Amazon, eBay', Gambling: 'Betting and casinos', AdultContent: 'Adult sites', Dating: 'Tinder, Bumble', Mining: 'Crypto mining pools', Crypto_Currency: 'Crypto exchanges and wallets'};
    var LABEL = {SocialNetwork: 'Social networks', AdultContent: 'Adult content', Crypto_Currency: 'Crypto currency', FileSharing: 'File sharing (P2P)', RemoteAccess: 'Remote access', VoIP: 'Calls (VoIP)', Game: 'Games'};

    L7.applyButton('#reconfigureAct', function () { load(); });
    L7.rememberTabs('app');
    L7.engineStatus('#l7-engine-pill');

    $('#grid-policies').UIBootgrid({
        search: '/api/layer7security/settings/search_policy',
        get: '/api/layer7security/settings/get_policy/',
        set: '/api/layer7security/settings/set_policy/',
        add: '/api/layer7security/settings/add_policy/',
        del: '/api/layer7security/settings/del_policy/',
        toggle: '/api/layer7security/settings/toggle_policy/',
        options: {
            requestHandler: function (request) { request.module = 'app'; return request; },
            formatters: { act: function (c, row) { return L7.tag(row.action === 'allow' ? '{{ lang._('Allow') }}' : (row.action === 'monitor' ? '{{ lang._('Watch') }}' : '{{ lang._('Block') }}'), row.action); } }
        }
    });

    function choice(group, key, value) {
        var name = 'c-' + group + '-' + key.replace(/[^A-Za-z0-9]/g, '_');
        function r(v, label) {
            return '<label style="margin-right:12px;font-weight:normal;cursor:pointer"><input type="radio" class="act-radio" data-group="' + group + '" data-key="' + E(key) + '" name="' + name + '" value="' + v + '"' + (value === v ? ' checked' : '') + '> ' + label + '</label>';
        }
        return r('allow', '{{ lang._('Allow') }}') + r('monitor', '{{ lang._('Watch') }}') + r('block', '<span style="color:var(--l7-bad)">{{ lang._('Block') }}</span>');
    }

    function load() {
        L7.get('/api/layer7security/appcontrol/state').done(function (d) {
            STATE = d; QUICK = d.quick || []; EDIT = {categories: {}, applications: {}};
            $('#tbl-appcats tbody').html(QUICK.map(function (c) {
                return '<tr><td><strong>' + E(LABEL[c] || c) + '</strong></td><td class="l7-muted">' + E(EXAMPLES[c] || '') + '</td><td>' + choice('categories', c, (d.categories || {})[c] || 'allow') + '</td></tr>';
            }).join(''));
            searchApps();
        });
        L7.get('/api/layer7security/appcontrol/status').done(function (d) {
            var c = d.counts || {};
            $('#l7-module-pill').replaceWith($(d.enabled ? (d.enforce ? L7.pill('{{ lang._('Blocking on') }}', 'ok') : L7.pill('{{ lang._('Watching only') }}', 'warn')) : L7.pill('{{ lang._('Engine off') }}', 'bad')).attr('id', 'l7-module-pill'));
            $('#app-tiles').html(
                L7.tile(c.rules || 0, '{{ lang._('Active rules') }}') +
                L7.tile(c.block || 0, '{{ lang._('Block rules') }}', '', c.block ? 'bad' : '') +
                L7.tile(c.monitor || 0, '{{ lang._('Watch rules') }}') +
                L7.tile(L7.num(LOG.length), '{{ lang._('Blocked in 24 h') }}', '', LOG.length ? 'warn' : '')
            );
        });
    }

    function searchApps() {
        L7.get('/api/layer7security/appcontrol/searchApps', {q: $('#app-q').val()}).done(function (d) {
            $('#app-total').text((d.total || 0) + ' {{ lang._('applications known') }}');
            $('#tbl-apps tbody').html((d.rows || []).map(function (a) {
                var v = EDIT.applications[a.name] || a.action;
                return '<tr><td><strong>' + E(a.name) + '</strong></td><td class="l7-muted">' + E(a.category) + '</td><td>' + choice('applications', a.name, v) + '</td></tr>';
            }).join('') || '<tr><td colspan="3">' + L7.empty('search', '{{ lang._('No application matches.') }}') + '</td></tr>');
        });
    }
    var t = null;
    $('#app-q').on('input', function () { clearTimeout(t); t = setTimeout(searchApps, 300); });

    $('.tab-content').on('change', '.act-radio', function () {
        EDIT[$(this).data('group')][$(this).data('key')] = $(this).val();
    });

    function save() {
        var body = {categories: JSON.stringify(EDIT.categories), applications: JSON.stringify(EDIT.applications)};
        if (!Object.keys(EDIT.categories).length && !Object.keys(EDIT.applications).length) { L7.toast('{{ lang._('Nothing was changed.') }}', 'warn'); return; }
        L7.post('/api/layer7security/appcontrol/save', body).done(function (r) {
            if (r && r.result === 'saved') { L7.pending(); L7.toast('{{ lang._('Saved. Click Apply changes to activate.') }}'); load(); }
            else { L7.toast('{{ lang._('Could not save.') }}', 'bad'); }
        });
    }
    $('#cats-save, #apps-save').on('click', save);

    function loadLog() {
        L7.get('/api/layer7security/live/events', {module: 'app', minutes: 1440, limit: 200}).done(function (d) {
            LOG = (d && d.rows) || [];
            $('#tbl-applog tbody').html(LOG.map(function (r) {
                return '<tr><td title="' + E(L7.when(r.ts)) + '">' + E(L7.ago(r.ts)) + '</td><td class="mono">' + E(r.client) + '</td><td>' + E(r.app) + ' <span class="l7-muted">' + E(r.category) + '</span></td><td class="trunc">' + E(r.host || r.server) + '</td><td>' + E(r.policy) + '</td></tr>';
            }).join('') || '<tr><td colspan="5">' + L7.empty('check-circle', '{{ lang._('Nothing was blocked yet.') }}') + '</td></tr>');
            load();
        });
    }
    $('a[href="#tab-activity"]').on('shown.bs.tab', loadLog);
    load();
    loadLog();
});
</script>
