<div class="l7">
    {{ partial('OPNsense/Layer7Security/partials/header', [
        'title': lang._('Antivirus'),
        'subtitle': lang._('Stops malware in downloads: known bad files, virus signatures and risky file types. The malware data comes from your cloud server.'),
        'icon': 'bug',
        'accent': 'prot',
        'apply': true
    ]) }}

    <div class="l7-tiles" id="av-tiles"></div>

    <ul class="nav nav-tabs" role="tablist">
        <li class="active"><a data-toggle="tab" href="#overview">{{ lang._('Overview') }}</a></li>
        <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
        <li><a data-toggle="tab" href="#detections">{{ lang._('Detections') }}</a></li>
        <li><a data-toggle="tab" href="#status">{{ lang._('Malware data') }}</a></li>
        <li><a data-toggle="tab" href="#tools">{{ lang._('Test a file') }}</a></li>
    </ul>

    <div class="tab-content">
        <div id="overview" class="tab-pane fade in active">
            <div id="av-state"></div>
            <div class="l7-grid2">
                <div class="l7-card"><h3>{{ lang._('How a download is checked') }}</h3>
                    <ol style="padding-left:18px;line-height:1.7">
                        <li>{{ lang._('The type of the file is recognised from its content (program, script, installer, archive).') }}</li>
                        <li>{{ lang._('Its MD5, SHA-1 and SHA-256 are looked up in the malware lists (cloud server, your own list, EICAR).') }}</li>
                        <li>{{ lang._('Virus signatures (YARA rules) are matched against the content.') }}</li>
                        <li>{{ lang._('Each result is allowed, logged or blocked as you chose under Settings.') }}</li>
                    </ol>
                </div>
                <div class="l7-card"><h3>{{ lang._('What it cannot do') }}</h3>
                    <ul style="padding-left:18px;line-height:1.7">
                        <li>{{ lang._('It is not a replacement for antivirus software on the computers.') }}</li>
                        <li>{{ lang._('Files inside archives and password-protected files are not opened.') }}</li>
                        <li>{{ lang._('HTTPS downloads are only seen for sites that DPI-SSL decrypts.') }}</li>
                    </ul>
                </div>
            </div>
        </div>

        <div id="settings" class="tab-pane fade">
            {{ partial("layout_partials/base_form", ['fields': antivirusForm, 'id': 'frm_antivirus']) }}
        </div>

        <div id="detections" class="tab-pane fade">
            <div class="l7-toolbar">
                <select id="av-period" class="form-control" style="width:auto">
                    <option value="3600">{{ lang._('Last hour') }}</option>
                    <option value="86400" selected="selected">{{ lang._('Last 24 hours') }}</option>
                    <option value="604800">{{ lang._('Last 7 days') }}</option>
                    <option value="2592000">{{ lang._('Last 30 days') }}</option>
                </select>
            </div>
            <table id="grid-av" class="table table-condensed table-hover table-striped" data-store-selection="false">
                <thead>
                    <tr>
                        <th data-column-id="id" data-type="numeric" data-identifier="true" data-visible="false">#</th>
                        <th data-column-id="ts" data-formatter="time" data-width="11em">{{ lang._('Time') }}</th>
                        <th data-column-id="action" data-formatter="action" data-width="6em">{{ lang._('Result') }}</th>
                        <th data-column-id="client" data-type="string">{{ lang._('Device') }}</th>
                        <th data-column-id="host" data-type="string">{{ lang._('Site') }}</th>
                        <th data-column-id="file" data-type="string">{{ lang._('File') }}</th>
                        <th data-column-id="size" data-type="numeric" data-width="7em">{{ lang._('Bytes') }}</th>
                        <th data-column-id="reason" data-type="string">{{ lang._('Reason') }}</th>
                        <th data-column-id="sha256" data-formatter="hash" data-width="9em">SHA-256</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>

        <div id="status" class="tab-pane fade">
            <div class="l7-toolbar">
                <button class="btn btn-primary" id="feedAct" type="button"><i class="fa fa-cloud-download"></i> {{ lang._('Update from the cloud server now') }}</button>
                <span id="feed-result"></span>
            </div>
            <div class="l7-grid2">
                <div class="l7-card"><h3>{{ lang._('Malware hashes') }}</h3><table class="l7-table" id="tbl-hashes"><thead><tr><th>{{ lang._('Kind') }}</th><th class="num">{{ lang._('Entries') }}</th><th>{{ lang._('Updated') }}</th></tr></thead><tbody></tbody></table></div>
                <div class="l7-card"><h3>{{ lang._('Virus signatures') }}</h3><dl class="l7-kv" id="sig-info"></dl></div>
            </div>
            <div class="l7-hint">{{ lang._('Hashes and signatures are collected by your cloud server from public sources (abuse.ch MalwareBazaar and ThreatFox, VirusShare and open YARA rule sets) and refreshed every few hours. The address of the cloud server is set under Protection > CFS > Settings.') }}</div>
        </div>

        <div id="tools" class="tab-pane fade">
            <div class="l7-grid2">
                <div class="l7-card">
                    <h3>{{ lang._('Scan a file') }}</h3>
                    <p class="l7-muted">{{ lang._('Choose a file on this computer to see what the download checks would say. The file is deleted straight away. Try the EICAR test file.') }}</p>
                    <div class="l7-toolbar">
                        <input type="file" id="scan-file" class="form-control grow"/>
                        <button class="btn btn-primary" id="scanAct" type="button"><i class="fa fa-search"></i> {{ lang._('Scan') }}</button>
                    </div>
                    <div id="scan-result"></div>
                </div>
                <div class="l7-card">
                    <h3>{{ lang._('Look up a hash') }}</h3>
                    <div class="l7-toolbar">
                        <input type="text" id="check-hash" class="form-control grow" placeholder="MD5, SHA-1 or SHA-256" maxlength="64"/>
                        <button class="btn btn-default" id="checkAct" type="button">{{ lang._('Check') }}</button>
                    </div>
                    <div id="check-result"></div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
$(document).ready(function () {
    var E = L7.esc, ST = {};
    L7.engineStatus('#l7-engine-pill');
    L7.rememberTabs('av');

    mapDataToFormUI({'frm_antivirus': '/api/layer7security/settings/get'}).done(function () { $('.selectpicker').selectpicker('refresh'); });

    $('#grid-av').UIBootgrid({
        search: '/api/layer7security/antivirus/search',
        options: {
            rowCount: [25, 50, 100, 250],
            requestHandler: function (request) { request.period = $('#av-period').val(); return request; },
            formatters: {
                time: function (c, row) { return E(new Date(row.ts * 1000).toLocaleString()); },
                action: function (c, row) { return row.action === 'blocked' ? L7.tag('{{ lang._('blocked') }}', 'block') : L7.tag('{{ lang._('logged') }}', 'monitor'); },
                hash: function (c, row) { return row.sha256 ? '<code title="' + E(row.sha256) + '">' + E(String(row.sha256).substr(0, 12)) + '</code>' : ''; }
            }
        }
    });
    $('#av-period').on('change', function () { $('#grid-av').bootgrid('reload'); });

    function loadStatus() {
        L7.get('/api/layer7security/antivirus/status').done(function (d) {
            ST = d || {};
            var sig = ST.signatures || {}, s = ST.icapStats || {};
            var on = ST.running;
            $('#l7-module-pill').replaceWith($(on ? L7.pill('{{ lang._('Antivirus on') }}', 'ok') : L7.pill('{{ lang._('Antivirus off') }}', 'warn')).attr('id', 'l7-module-pill'));
            $('#av-tiles').html(
                L7.tile(on ? '{{ lang._('Running') }}' : '{{ lang._('Off') }}', '{{ lang._('Scanner') }}', '', on ? 'ok' : 'warn') +
                L7.tile(L7.num(ST.hashes || 0), '{{ lang._('Malware hashes') }}') +
                L7.tile(L7.num(sig.rules || 0), '{{ lang._('Signature rules') }}', sig.ready ? '' : '{{ lang._('not downloaded') }}', sig.ready ? '' : 'warn') +
                L7.tile(L7.num(ST.detections24h || 0), '{{ lang._('Detections in 24 h') }}', '', ST.detections24h ? 'warn' : '') +
                L7.tile(L7.num(ST.blocked24h || 0), '{{ lang._('Blocked in 24 h') }}', '', ST.blocked24h ? 'bad' : '') +
                L7.tile(L7.num(s.requests || 0), '{{ lang._('Files checked') }}')
            );
            var msg = '';
            if (!on) { msg = '<div class="l7-hint warn">{{ lang._('Antivirus is switched off. Turn it on under Settings and click Apply changes.') }}</div>'; }
            else if (!sig.installed) { msg = '<div class="l7-hint warn">{{ lang._('The signature scanner (package yara) is not installed. Hashes and file types still work.') }}</div>'; }
            else if (!sig.ready && ST.yaraAction !== 'off') { msg = '<div class="l7-hint warn">{{ lang._('Signatures are not downloaded yet. Open "Malware data" and click Update.') }}</div>'; }
            $('#av-state').html(msg);
            var h = ST.hashesByType || {};
            $('#tbl-hashes tbody').html([['SHA-256', h.sha256], ['SHA-1', h.sha1], ['MD5', h.md5]].map(function (r) { return '<tr><td>' + r[0] + '</td><td class="num">' + L7.num(r[1] || 0) + '</td><td>' + (ST.feedTs ? E(L7.ago(ST.feedTs)) : '-') + '</td></tr>'; }).join(''));
            $('#sig-info').html([['{{ lang._('Scanner installed') }}', sig.installed ? '{{ lang._('yes') }}' : '{{ lang._('no') }}'], ['{{ lang._('Rules loaded') }}', L7.num(sig.rules || 0)],
                ['{{ lang._('Rule files') }}', (sig.files || 0) + (sig.rejected ? ' (' + sig.rejected + ' {{ lang._('rejected') }})' : '')], ['{{ lang._('Updated') }}', sig.ts ? L7.ago(sig.ts) : '-'],
                ['{{ lang._('Mode') }}', ST.yaraAction || '-']].map(function (p) { return '<dt>' + E(p[0]) + '</dt><dd>' + E(p[1]) + '</dd>'; }).join(''));
        });
    }

    L7.applyButton('#reconfigureAct', function () { loadStatus(); $('#grid-av').bootgrid('reload'); }, ['frm_antivirus']);

    $('#feedAct').on('click', function () {
        $('#feed-result').html('<i class="fa fa-spinner fa-pulse"></i>');
        L7.post('/api/layer7security/antivirus/feed_update', {}).done(function (d) {
            if (d && d.updated) { $('#feed-result').html(L7.pill('{{ lang._('Updated') }}', 'ok')); }
            else { $('#feed-result').html(L7.pill((d && d.error) || '{{ lang._('Nothing was updated.') }}', 'bad')); }
            loadStatus();
        });
    });

    $('#checkAct').on('click', function () {
        L7.post('/api/layer7security/antivirus/check', {hash: $('#check-hash').val()}).done(function (d) {
            if (!d) { return; }
            if (d.error) { $('#check-result').html('<div class="l7-hint warn">' + E(d.error) + '</div>'); return; }
            $('#check-result').html(d.known
                ? '<div class="l7-hint bad"><strong>{{ lang._('Known malware.') }}</strong> ' + (d.eicar ? '{{ lang._('This is the EICAR test file.') }}' : '{{ lang._('This hash is on the block list.') }}') + (d.family ? ' (' + E(d.family) + ')' : '') + '</div>'
                : '<div class="l7-hint ok">{{ lang._('Not on any malware list.') }}</div>');
        });
    });

    $('#scanAct').on('click', function () {
        var f = $('#scan-file')[0].files[0];
        if (!f) { return; }
        var fd = new FormData();
        fd.append('file', f);
        $('#scan-result').html('<i class="fa fa-spinner fa-pulse"></i>');
        $.ajax({url: '/api/layer7security/antivirus/scanFile', type: 'POST', data: fd, processData: false, contentType: false, dataType: 'json'}).done(function (d) {
            if (!d || d.error) { $('#scan-result').html('<div class="l7-hint warn">' + E((d && d.error) || 'failed') + '</div>'); return; }
            var cls = d.verdict === 'malware' ? 'bad' : (d.verdict === 'risky type' ? 'warn' : 'ok');
            var title = d.verdict === 'malware' ? '{{ lang._('Malware found') }}' : (d.verdict === 'risky type' ? '{{ lang._('Risky type of file') }}' : '{{ lang._('Nothing found') }}');
            var kv = [['{{ lang._('File') }}', d.name + ' (' + L7.bytes(d.size) + ')'], ['{{ lang._('Type') }}', d.label || '{{ lang._('ordinary file') }}'], ['SHA-256', d.digests.sha256], ['SHA-1', d.digests.sha1], ['MD5', d.digests.md5],
                      ['{{ lang._('On a malware list') }}', d.known ? (d.eicar ? 'EICAR' : '{{ lang._('yes') }}' + (d.family ? ' (' + d.family + ')' : '')) : '{{ lang._('no') }}'],
                      ['{{ lang._('Signatures') }}', (d.signatures || []).length ? d.signatures.join(', ') : (d.signaturesReady ? '{{ lang._('none matched') }}' : '{{ lang._('not available') }}')]];
            $('#scan-result').html('<div class="l7-hint ' + cls + '"><strong>' + title + '</strong></div><dl class="l7-kv">' + kv.map(function (p) { return '<dt>' + E(p[0]) + '</dt><dd class="mono">' + E(p[1]) + '</dd>'; }).join('') + '</dl>');
        }).fail(function () { $('#scan-result').html('<div class="l7-hint warn">{{ lang._('The upload failed.') }}</div>'); });
    });

    loadStatus();
    setInterval(loadStatus, 20000);
});
</script>
