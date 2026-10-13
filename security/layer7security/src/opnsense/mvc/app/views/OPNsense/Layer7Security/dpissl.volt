<div class="l7">
    {{ partial('OPNsense/Layer7Security/partials/header', [
        'title': lang._('DPI-SSL'),
        'subtitle': lang._('Look inside encrypted (HTTPS) traffic so that downloads can be scanned and content rules can work. Sites you exclude are never opened.'),
        'icon': 'lock',
        'accent': 'prot',
        'apply': true
    ]) }}

    <div class="l7-tiles" id="dpi-tiles"></div>

    <ul class="nav nav-tabs" role="tablist">
        <li class="active"><a data-toggle="tab" href="#tab-overview">{{ lang._('Overview') }}</a></li>
        <li><a data-toggle="tab" href="#tab-settings">{{ lang._('Settings') }}</a></li>
        <li><a data-toggle="tab" href="#tab-cert">{{ lang._('Certificate') }}</a></li>
        <li><a data-toggle="tab" href="#tab-log">{{ lang._('Sessions') }}</a></li>
    </ul>

    <div class="tab-content">
        <div id="tab-overview" class="tab-pane fade in active">
            <div id="dpi-state"></div>
            <div class="l7-grid2">
                <div class="l7-card">
                    <h3>{{ lang._('What is decrypted now') }}</h3>
                    <div id="dpi-scope"></div>
                </div>
                <div class="l7-card">
                    <h3>{{ lang._('Checklist') }}</h3>
                    <div id="dpi-check"></div>
                </div>
            </div>
            <div class="l7-hint warn">
                {{ lang._('Decrypting traffic is a serious step. Tell the people concerned, keep to your local law, install the certificate only on devices you manage, and keep banks and health sites on the exclusion list.') }}
            </div>
        </div>

        <div id="tab-settings" class="tab-pane fade">
            {{ partial("layout_partials/base_form", ['fields': dpiForm, 'id': 'frm_dpi']) }}
            <button class="btn btn-primary" id="dpi-save" type="button"><i class="fa fa-save"></i> {{ lang._('Save') }}</button>
            <h3 style="margin-top:24px">{{ lang._('Sites that are skipped by default') }}</h3>
            <p class="l7-muted">{{ lang._('These keep working because they refuse decrypted connections (certificate pinning) or are privacy sensitive.') }}</p>
            <div id="dpi-defaults" class="l7-muted" style="columns:3 220px;font-family:monospace;font-size:12px"></div>
        </div>

        <div id="tab-cert" class="tab-pane fade">
            <div class="l7-card">
                <h3>{{ lang._('The DPI-SSL certificate') }}</h3>
                <p class="l7-muted" style="max-width:820px">
                    {{ lang._('Decrypted connections are re-encrypted with certificates issued by this firewall. Every device must trust the certificate below. A restricted certificate can only be used for the sites you list, so it cannot impersonate other sites even if its key were stolen. It is valid for two years.') }}
                </p>
                <dl class="l7-kv" id="ca-details" style="display:none"></dl>
                <div id="ca-state"></div>
                <div class="l7-toolbar" style="margin-top:12px">
                    <button class="btn btn-primary" id="caDownload" type="button" style="display:none"><i class="fa fa-download"></i> {{ lang._('Download the certificate') }}</button>
                    <button class="btn btn-default" id="caNew" type="button"><i class="fa fa-refresh"></i> {{ lang._('Create a new certificate') }}</button>
                </div>
            </div>
            <div class="l7-card">
                <h3>{{ lang._('Installing it on a device') }}</h3>
                <ul style="max-width:820px">
                    <li><strong>Windows</strong>: {{ lang._('double-click the file, Install Certificate, Local Machine, place it in "Trusted Root Certification Authorities".') }}</li>
                    <li><strong>macOS</strong>: {{ lang._('open it in Keychain Access, add to System, set Trust to Always Trust.') }}</li>
                    <li><strong>Linux</strong>: {{ lang._('copy it to /usr/local/share/ca-certificates/ as .crt and run update-ca-certificates. Firefox keeps its own store.') }}</li>
                    <li><strong>Android / iOS</strong>: {{ lang._('install it as a CA certificate; apps that pin certificates will refuse to connect through decryption.') }}</li>
                </ul>
            </div>
        </div>

        <div id="tab-log" class="tab-pane fade">
            <div class="l7-hint">{{ lang._('Recent connections handled by the decryption proxy. "Decrypted" connections were opened and scanned, "Passed" connections were left alone.') }}</div>
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-dpilog">
                    <thead><tr><th>{{ lang._('Time') }}</th><th>{{ lang._('Device') }}</th><th>{{ lang._('Site') }}</th><th>{{ lang._('Handled') }}</th><th>{{ lang._('Result') }}</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script>
$(document).ready(function () {
    var E = L7.esc, STATUS = {}, CA = {};
    L7.applyButton('#reconfigureAct', function () { loadAll(); }, ['frm_dpi']);
    L7.rememberTabs('dpi');
    L7.engineStatus('#l7-engine-pill');

    mapDataToFormUI({'frm_dpi': '/api/layer7security/settings/get'}).done(function () { $('.selectpicker').selectpicker('refresh'); });
    $('#dpi-save').on('click', function () {
        saveFormToEndpoint('/api/layer7security/settings/set', 'frm_dpi', function () {
            L7.pending();
            L7.toast('{{ lang._('Saved. Click Apply changes to activate.') }}');
        });
    });

    function loadCa() {
        L7.get('/api/layer7security/inspection/ca_info').done(function (d) {
            CA = d || {};
            if (!d || !d.exists) {
                $('#ca-state').html(L7.pill('{{ lang._('not created yet') }}', 'warn') + ' <span class="l7-muted">{{ lang._('It is created on the first Apply with DPI-SSL, AI inspection or antivirus on HTTPS turned on.') }}</span>');
                $('#ca-details, #caDownload').hide();
            } else {
                var kv = [['{{ lang._('Type') }}', d.mode === 'full' ? '{{ lang._('Full: can sign any site') }}' : '{{ lang._('Restricted: only the listed sites') }}'],
                          ['{{ lang._('Subject') }}', d.subject], ['{{ lang._('SHA-256 fingerprint') }}', d.fingerprint],
                          ['{{ lang._('Valid') }}', d.notBefore + '  ->  ' + d.notAfter],
                          ['{{ lang._('Permitted sites') }}', (d.constraints || []).length ? d.constraints.join(', ') : '{{ lang._('any site') }}']];
                $('#ca-details').html(kv.map(function (p) { return '<dt>' + E(p[0]) + '</dt><dd>' + E(p[1]) + '</dd>'; }).join('')).show();
                $('#ca-state').html(L7.pill('{{ lang._('present') }}', 'ok'));
                $('#caDownload').show();
            }
            overview();
        });
    }

    function loadStatus() {
        L7.get('/api/layer7security/inspection/status').done(function (d) { STATUS = d || {}; overview(); });
        L7.get('/api/layer7security/settings/get').done(function (d) { STATUS.cfg = (d && d.layer7security) || {}; overview(); });
    }

    function sel(o) {
        if (o === null || o === undefined) { return ''; }
        if (typeof o === 'string') { return o; }
        return Object.keys(o).filter(function (k) { return o[k] && o[k].selected; }).join(',');
    }

    function overview() {
        var c = STATUS.cfg;
        if (!c || !c.dpi) { return; }
        var on = c.dpi.enabled === '1', scope = sel(c.dpi.scope) || 'selected';
        var run = STATUS.running;
        var pill = !on ? L7.pill('{{ lang._('DPI-SSL off') }}', 'plain') : (run ? L7.pill('{{ lang._('DPI-SSL on') }}', 'ok') : L7.pill('{{ lang._('DPI-SSL not running') }}', 'bad'));
        $('#l7-module-pill').replaceWith($(pill).attr('id', 'l7-module-pill'));
        var s = STATUS.icapStats || {};
        $('#dpi-tiles').html(
            L7.tile(on ? (scope === 'all' ? '{{ lang._('All HTTPS') }}' : '{{ lang._('Listed sites') }}') : '{{ lang._('Off') }}', '{{ lang._('Mode') }}') +
            L7.tile(run ? '{{ lang._('Running') }}' : '{{ lang._('Stopped') }}', '{{ lang._('Decryption proxy') }}', '', run ? 'ok' : (on ? 'bad' : '')) +
            L7.tile(CA.exists ? (CA.mode === 'full' ? '{{ lang._('Full') }}' : '{{ lang._('Restricted') }}') : '-', '{{ lang._('Certificate') }}', CA.exists ? CA.notAfter : '') +
            L7.tile(L7.num(s.requests || 0), '{{ lang._('Requests scanned') }}') +
            L7.tile(L7.num((s.detections || 0)), '{{ lang._('Detections') }}', '', s.detections ? 'warn' : '') +
            L7.tile(L7.num(s.blocked || 0), '{{ lang._('Blocked') }}', '', s.blocked ? 'bad' : '')
        );
        var items = [];
        if (!on) { items.push('{{ lang._('Nothing is decrypted by DPI-SSL.') }}'); }
        else if (scope === 'all') { items.push('<strong>{{ lang._('All HTTPS') }}</strong> {{ lang._('except the exclusions') }}'); }
        else { items.push('<strong>{{ lang._('Only the sites you listed') }}</strong>'); }
        if (c.dlp && c.dlp.enabled === '1') { items.push('{{ lang._('AI services chosen for inspection (AI Inspection)') }}'); }
        if (c.av && c.av.enabled === '1' && c.av.httpsDomains) { items.push('{{ lang._('Antivirus download sites:') }} ' + E(sel(c.av.httpsDomains))); }
        $('#dpi-scope').html('<ul style="padding-left:18px">' + items.map(function (x) { return '<li>' + x + '</li>'; }).join('') + '</ul>');
        var ack = c.audit && c.audit.privacyAckBy;
        var chk = [
            [ack, '{{ lang._('Privacy notice acknowledged') }}', '{{ lang._('Acknowledge it under AI > AI Audit > Privacy') }}'],
            [CA.exists, '{{ lang._('Certificate created') }}', '{{ lang._('It is created on Apply') }}'],
            [run || !on, '{{ lang._('Decryption proxy running') }}', '{{ lang._('Click Apply changes') }}'],
            [!(on && scope === 'all' && CA.exists && CA.mode !== 'full'), '{{ lang._('Certificate type fits the mode') }}', '{{ lang._('Mode "All HTTPS" needs a full certificate: set Certificate type to Full, Save, then create a new certificate') }}']
        ];
        $('#dpi-check').html(chk.map(function (r) {
            return '<div style="margin:6px 0">' + (r[0] ? '<i class="fa fa-check-circle" style="color:var(--l7-ok)"></i> ' + E(r[1]) :
                '<i class="fa fa-exclamation-circle" style="color:var(--l7-warn)"></i> ' + E(r[1]) + ' <span class="l7-muted">- ' + E(r[2]) + '</span>') + '</div>';
        }).join(''));
    }

    function loadLog() {
        L7.get('/api/layer7security/inspection/log', {rows: 200}).done(function (d) {
            var rows = ((d && d.rows) || []).filter(function (r) { return r.result !== 'NONE_NONE'; });
            $('#tbl-dpilog tbody').html(rows.map(function (r) {
                var dec = r.mode === 'bump' || r.mode === 'client-first' || r.mode === 'server-first';
                return '<tr><td title="' + E(L7.when(r.ts)) + '">' + E(L7.ago(r.ts)) + '</td><td class="mono">' + E(r.client) + '</td><td class="trunc">' + E(r.sni || r.url) + '</td>' +
                    '<td>' + (dec ? L7.tag('{{ lang._('Decrypted') }}', 'monitor') : L7.tag('{{ lang._('Passed') }}', '')) + '</td><td>' + E(r.result) + ' ' + E(r.status) + '</td></tr>';
            }).join('') || '<tr><td colspan="5">' + L7.empty('lock', '{{ lang._('No sessions yet.') }}') + '</td></tr>');
        });
    }

    function loadDefaults() {
        L7.get('/api/layer7security/inspection/defaults').done(function (d) {
            $('#dpi-defaults').html(((d && d.rows) || []).map(function (x) { return E(x) + '<br>'; }).join(''));
        });
    }

    function loadAll() { loadStatus(); loadCa(); }

    $('#caDownload').on('click', function () { window.location = '/api/layer7security/inspection/ca'; });
    $('#caNew').on('click', function () {
        L7.confirm({title: '{{ lang._('Create a new certificate?') }}', danger: true, yes: '{{ lang._('Create') }}',
            message: E('{{ lang._('Every device has to trust the new certificate afterwards, or decrypted sites show certificate errors. The type follows the setting "Certificate type" (saved settings).') }}'),
            onYes: function () { L7.post('/api/layer7security/inspection/ca_new').done(function () { loadAll(); L7.toast('{{ lang._('A new certificate was created.') }}'); }); }});
    });
    $('a[href="#tab-log"]').on('shown.bs.tab', loadLog);
    loadAll();
    loadDefaults();
    setInterval(loadStatus, 15000);
});
</script>
