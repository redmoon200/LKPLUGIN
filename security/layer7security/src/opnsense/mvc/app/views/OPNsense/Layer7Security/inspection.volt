<div class="l7">
    {{ partial('OPNsense/Layer7Security/partials/header', [
        'title': lang._('AI Inspection'),
        'subtitle': lang._('Look at what people send to AI services and stop card numbers, ID numbers, passwords and source code before they leave.'),
        'icon': 'search',
        'accent': 'ai',
        'apply': true
    ]) }}

    <div class="l7-tiles" id="in-tiles"></div>

    <ul class="nav nav-tabs" role="tablist">
        <li class="active"><a data-toggle="tab" href="#overview">{{ lang._('Overview') }}</a></li>
        <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
        <li><a data-toggle="tab" href="#test">{{ lang._('Test the detectors') }}</a></li>
        <li><a data-toggle="tab" href="#activity">{{ lang._('Detections') }}</a></li>
    </ul>

    <div class="tab-content">
        <div id="overview" class="tab-pane fade in active">
            <div id="in-state"></div>
            <div class="l7-grid2">
                <div class="l7-card"><h3>{{ lang._('Checklist') }}</h3><div id="in-check"></div></div>
                <div class="l7-card"><h3>{{ lang._('What is looked for') }}</h3>
                    <ul style="padding-left:18px;line-height:1.7">
                        <li>{{ lang._('Payment card numbers (checked with the card checksum)') }}</li>
                        <li>{{ lang._('Identity numbers: SSN, Aadhaar, PAN, IBAN, UK NINO') }}</li>
                        <li>{{ lang._('API keys, private keys and tokens') }}</li>
                        <li>{{ lang._('Source code') }}</li>
                    </ul>
                    <p class="l7-muted">{{ lang._('Only masked excerpts are ever stored, for example **** **** **** 1111.') }}</p>
                </div>
            </div>
            <div class="l7-hint warn">
                {{ lang._('This looks into encrypted traffic to the AI services you pick. Acknowledge the privacy notice (AI Audit > Privacy), tell the people concerned, and install the DPI-SSL certificate on managed devices.') }}
                <a href="/ui/layer7security/dpissl">{{ lang._('Open DPI-SSL') }}</a>
            </div>
        </div>

        <div id="settings" class="tab-pane fade">
            {{ partial("layout_partials/base_form", ['fields': inspectionForm, 'id': 'frm_inspection']) }}
            <button class="btn btn-primary" id="in-save" type="button"><i class="fa fa-save"></i> {{ lang._('Save') }}</button>
            <div class="l7-hint" style="margin-top:14px">{{ lang._('Choose which AI services are checked under AI > AI Service > Services ("Check content").') }}</div>
        </div>

        <div id="test" class="tab-pane fade">
            <div class="l7-card">
                <p class="l7-muted" style="max-width:820px">
                    {{ lang._('Paste text to see what the detectors would find with the saved settings. Nothing is stored or logged and the text is deleted immediately.') }}
                </p>
                <textarea id="test-text" class="form-control" rows="8" style="max-width:820px"
                          placeholder="{{ lang._('For example: my card is 4111 1111 1111 1111') }}"></textarea>
                <br/>
                <button class="btn btn-primary" id="testAct" type="button"><i class="fa fa-search"></i> {{ lang._('Scan') }}</button>
                <div id="test-result" style="margin-top:12px;max-width:900px"></div>
            </div>
        </div>

        <div id="activity" class="tab-pane fade">
            <div class="l7-hint">{{ lang._('Everything the detectors found is recorded, masked, in AI Audit.') }} <a href="/ui/layer7security/audit">{{ lang._('Open AI Audit') }}</a></div>
            <div class="l7-scroll">
                <table class="l7-table" id="tbl-det">
                    <thead><tr><th>{{ lang._('Time') }}</th><th>{{ lang._('Device') }}</th><th>{{ lang._('Service') }}</th><th>{{ lang._('Found') }}</th><th>{{ lang._('Result') }}</th><th>{{ lang._('Excerpt') }}</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script>
$(document).ready(function () {
    var E = L7.esc, ST = {}, CFG = {};
    L7.applyButton('#reconfigureAct', function () { load(); }, ['frm_inspection']);
    L7.rememberTabs('inspection');
    L7.engineStatus('#l7-engine-pill');

    mapDataToFormUI({'frm_inspection': '/api/layer7security/settings/get'}).done(function () { $('.selectpicker').selectpicker('refresh'); });
    $('#in-save').on('click', function () {
        saveFormToEndpoint('/api/layer7security/settings/set', 'frm_inspection', function () { L7.pending(); L7.toast('{{ lang._('Saved. Click Apply changes to activate.') }}'); load(); });
    });

    function load() {
        L7.get('/api/layer7security/inspection/status').done(function (d) { ST = d || {}; draw(); });
        L7.get('/api/layer7security/settings/get').done(function (d) { CFG = (d && d.layer7security) || {}; draw(); });
    }

    function draw() {
        if (!CFG.dlp) { return; }
        var on = CFG.dlp.enabled === '1', s = ST.icapStats || {}, run = ST.running;
        $('#l7-module-pill').replaceWith($(on ? (run ? L7.pill('{{ lang._('Inspection on') }}', 'ok') : L7.pill('{{ lang._('Inspection not running') }}', 'bad')) : L7.pill('{{ lang._('Inspection off') }}', 'plain')).attr('id', 'l7-module-pill'));
        $('#in-tiles').html(
            L7.tile(on ? '{{ lang._('On') }}' : '{{ lang._('Off') }}', '{{ lang._('AI inspection') }}', '', on ? 'ok' : '') +
            L7.tile(run ? '{{ lang._('Running') }}' : '{{ lang._('Stopped') }}', '{{ lang._('Inspection proxy') }}', '', run ? 'ok' : (on ? 'bad' : '')) +
            L7.tile(L7.num(s.requests || 0), '{{ lang._('Requests checked') }}') +
            L7.tile(L7.num(s.detections || 0), '{{ lang._('Detections') }}', '', s.detections ? 'warn' : '') +
            L7.tile(L7.num(s.blocked || 0), '{{ lang._('Blocked') }}', '', s.blocked ? 'bad' : '') +
            L7.tile(L7.num(s.errors || 0), '{{ lang._('Scanner errors') }}', '', s.errors ? 'bad' : '')
        );
        var ack = CFG.audit && CFG.audit.privacyAckBy;
        var checks = [[ack, '{{ lang._('Privacy notice acknowledged') }}', '{{ lang._('AI > AI Audit > Privacy') }}'],
                      [on, '{{ lang._('AI inspection enabled') }}', '{{ lang._('Settings tab') }}'],
                      [run, '{{ lang._('Inspection proxy running') }}', '{{ lang._('Click Apply changes') }}']];
        $('#in-check').html(checks.map(function (r) {
            return '<div style="margin:6px 0">' + (r[0] ? '<i class="fa fa-check-circle" style="color:var(--l7-ok)"></i> ' + E(r[1]) :
                '<i class="fa fa-exclamation-circle" style="color:var(--l7-warn)"></i> ' + E(r[1]) + ' <span class="l7-muted">- ' + E(r[2]) + '</span>') + '</div>';
        }).join(''));
        $('#in-state').html(on && !ack ? '<div class="l7-hint bad">{{ lang._('The privacy notice has not been acknowledged, so nothing can be applied yet.') }}</div>' : '');
    }

    $('#testAct').on('click', function () {
        $('#test-result').html('<i class="fa fa-spinner fa-pulse"></i>');
        L7.post('/api/layer7security/inspection/test', {text: $('#test-text').val()}).done(function (d) {
            if (!d || !d.detections) { $('#test-result').text(''); return; }
            if (d.detections.length === 0) {
                $('#test-result').html('<div class="l7-hint ok">{{ lang._('Nothing sensitive detected.') }}</div>');
                return;
            }
            var html = '<table class="l7-table"><thead><tr><th>{{ lang._('Category') }}</th><th>{{ lang._('Rule') }}</th><th>{{ lang._('Would') }}</th><th>{{ lang._('Masked excerpt') }}</th></tr></thead><tbody>';
            d.detections.forEach(function (x) {
                html += '<tr><td>' + E(x.category) + '</td><td>' + E(x.rule) + '</td><td>' + E(x.action) + '</td><td><code>' + E(x.masked) + '</code></td></tr>';
            });
            $('#test-result').html(html + '</tbody></table>');
        });
    });

    function loadDet() {
        L7.post('/api/layer7security/audit/search', {rowCount: 50, current: 1, searchPhrase: 'dlp', period: 604800}).done(function (d) {
            var rows = (d && d.rows) || [];
            $('#tbl-det tbody').html(rows.map(function (r) {
                return '<tr><td title="' + E(L7.when(r.ts)) + '">' + E(L7.ago(r.ts)) + '</td><td class="mono">' + E(r.client) + '</td><td>' + E(r.service) + '</td><td>' + E(r.category) + '</td><td>' + (r.action === 'blocked' ? L7.tag('{{ lang._('blocked') }}', 'block') : L7.tag('{{ lang._('logged') }}', 'monitor')) + '</td><td><code>' + E(r.detail || '') + '</code></td></tr>';
            }).join('') || '<tr><td colspan="6">' + L7.empty('check-circle', '{{ lang._('Nothing sensitive was found yet.') }}') + '</td></tr>');
        });
    }
    $('a[href="#activity"]').on('shown.bs.tab', loadDet);
    load();
    setInterval(load, 15000);
});
</script>
