<script>
    $(document).ready(function () {
        function esc(value) {
            return $('<div>').text(value === null || value === undefined ? '' : String(value)).html();
        }

        mapDataToFormUI({ 'frm_inspection': '/api/layer7security/settings/get' }).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });

        function loadStatus() {
            ajaxGet('/api/layer7security/inspection/status', {}, function (d) {
                if (!d) { return; }
                const s = d.icapStats || {};
                $('#in-proxy').html(d.running ? '<span class="label label-success">{{ lang._("running") }}</span>' : '<span class="label label-default">{{ lang._("stopped") }}</span>');
                $('#in-squid').text(d.squid ? "{{ lang._('running') }}" : "{{ lang._('stopped') }}");
                $('#in-icap').text(d.icap ? "{{ lang._('running') }}" : "{{ lang._('stopped') }}");
                $('#in-req').text(s.requests === undefined ? '-' : s.requests);
                $('#in-det').text(s.detections === undefined ? '-' : s.detections);
                $('#in-blk').text(s.blocked === undefined ? '-' : s.blocked);
                $('#in-err').text(s.errors === undefined ? '-' : s.errors);
            });
        }

        function loadCa() {
            ajaxGet('/api/layer7security/inspection/ca_info', {}, function (d) {
                if (!d || !d.exists) {
                    $('#ca-state').html('<span class="label label-default">{{ lang._("not created yet") }}</span> {{ lang._("It is created on the first Apply with inspection enabled.") }}');
                    $('#ca-details, #caDownload').hide();
                    return;
                }
                $('#ca-state').html('<span class="label label-success">{{ lang._("present") }}</span>');
                $('#ca-subject').text(d.subject);
                $('#ca-fp').text(d.fingerprint);
                $('#ca-valid').text(d.notBefore + '  ->  ' + d.notAfter);
                $('#ca-nc').text((d.constraints || []).length ? (d.constraints || []).join(', ') : "{{ lang._('none') }}");
                $('#ca-details, #caDownload').show();
            });
        }
        loadStatus();
        loadCa();
        setInterval(loadStatus, 10000);

        $('#caDownload').click(function () { window.location = '/api/layer7security/inspection/ca'; });
        $('#caNew').click(function () {
            stdDialogConfirm("{{ lang._('Replace the inspection CA?') }}",
                "{{ lang._('Every client must install the new certificate afterwards, or inspected services will show certificate errors.') }}",
                "{{ lang._('Replace') }}", "{{ lang._('Cancel') }}", function () {
                    ajaxCall('/api/layer7security/inspection/ca_new', {}, function () { loadCa(); loadStatus(); });
                });
        });

        $('#testAct').click(function () {
            $('#test-result').html('<i class="fa fa-spinner fa-pulse"></i>');
            ajaxCall('/api/layer7security/inspection/test', { text: $('#test-text').val() }, function (d) {
                if (!d || !d.detections) { $('#test-result').text(''); return; }
                if (d.detections.length === 0) {
                    $('#test-result').html('<div class="alert alert-success">{{ lang._("Nothing sensitive detected.") }}</div>');
                    return;
                }
                let html = '<table class="table table-condensed table-striped"><thead><tr><th>{{ lang._("Category") }}</th><th>{{ lang._("Rule") }}</th><th>{{ lang._("Would") }}</th><th>{{ lang._("Masked excerpt") }}</th></tr></thead><tbody>';
                d.detections.forEach(function (x) {
                    html += '<tr><td>' + esc(x.category) + '</td><td>' + esc(x.rule) + '</td><td>' + esc(x.action) + '</td><td><code>' + esc(x.masked) + '</code></td></tr>';
                });
                $('#test-result').html(html + '</tbody></table>');
            });
        });

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function () {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/layer7security/settings/set", 'frm_inspection', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
                return dfObj;
            },
            onAction: function (data, status) {
                if (data && data.status === 'failed') {
                    BootstrapDialog.show({
                        type: BootstrapDialog.TYPE_DANGER,
                        title: "{{ lang._('Apply failed') }}",
                        message: $('<div>').text(data.message || '').html()
                    });
                }
                loadStatus();
                loadCa();
            }
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#cert">{{ lang._('Certificate') }}</a></li>
    <li><a data-toggle="tab" href="#status">{{ lang._('Status') }}</a></li>
    <li><a data-toggle="tab" href="#test">{{ lang._('Test the detectors') }}</a></li>
</ul>
<div class="tab-content content-box">
    <div id="settings" class="tab-pane fade in active">
        <div class="alert alert-warning" style="margin: 10px;">
            {{ lang._('This feature decrypts traffic to the selected AI services. Read and acknowledge the privacy notice (AI Audit > Privacy) and make sure the people concerned are informed before you enable it. Choose which services to inspect in AI Services > Rules ("Inspect content").') }}
        </div>
        {{ partial("layout_partials/base_form", ['fields': inspectionForm, 'id': 'frm_inspection']) }}
    </div>
    <div id="cert" class="tab-pane fade in">
        <p style="margin-top: 10px; max-width: 820px;">
            {{ lang._('Inspected services are re-encrypted with certificates issued by this firewall. Clients must trust the inspection CA below; install it only on devices you own or manage. The CA is restricted (X.509 name constraints) to the AI service domains of the catalog, so it cannot be used to impersonate other sites even if its key were stolen. It is valid for two years.') }}
        </p>
        <p><strong>{{ lang._('State') }}:</strong> <span id="ca-state">-</span></p>
        <table class="table table-condensed" id="ca-details" style="max-width: 820px; display: none;">
            <tr><th>{{ lang._('Subject') }}</th><td id="ca-subject"></td></tr>
            <tr><th>{{ lang._('SHA-256 fingerprint') }}</th><td><code id="ca-fp"></code></td></tr>
            <tr><th>{{ lang._('Valid') }}</th><td id="ca-valid"></td></tr>
            <tr><th>{{ lang._('Permitted domains') }}</th><td id="ca-nc" style="word-break: break-word;"></td></tr>
        </table>
        <button class="btn btn-primary" id="caDownload" type="button" style="display: none;"><span class="fa fa-download"></span> {{ lang._('Download the CA certificate') }}</button>
        <button class="btn btn-default" id="caNew" type="button"><span class="fa fa-refresh"></span> {{ lang._('Replace the CA') }}</button>
        <h3>{{ lang._('Installing it on a client') }}</h3>
        <ul style="max-width: 820px;">
            <li><strong>Windows</strong>: {{ lang._('double-click the file, Install Certificate, Local Machine, place it in "Trusted Root Certification Authorities".') }}</li>
            <li><strong>macOS</strong>: {{ lang._('open it in Keychain Access, add to System, set Trust to Always Trust.') }}</li>
            <li><strong>Linux</strong>: {{ lang._('copy it to /usr/local/share/ca-certificates/ as .crt and run update-ca-certificates. Firefox keeps its own store.') }}</li>
            <li><strong>Android / iOS</strong>: {{ lang._('install it as a CA certificate; apps that pin certificates will refuse to connect through inspection.') }}</li>
        </ul>
    </div>
    <div id="status" class="tab-pane fade in">
        <table class="table table-condensed" style="max-width: 560px; margin-top: 10px;">
            <tr><th>{{ lang._('Inspection proxy') }}</th><td id="in-proxy">-</td></tr>
            <tr><th>Squid</th><td id="in-squid">-</td></tr>
            <tr><th>{{ lang._('ICAP scanner') }}</th><td id="in-icap">-</td></tr>
            <tr><th>{{ lang._('Requests scanned') }}</th><td id="in-req">-</td></tr>
            <tr><th>{{ lang._('Detections') }}</th><td id="in-det">-</td></tr>
            <tr><th>{{ lang._('Requests blocked') }}</th><td id="in-blk">-</td></tr>
            <tr><th>{{ lang._('Scanner errors') }}</th><td id="in-err">-</td></tr>
        </table>
        <p class="text-muted">{{ lang._('Detections are recorded, masked, in AI Audit.') }}</p>
    </div>
    <div id="test" class="tab-pane fade in">
        <p style="margin-top: 10px; max-width: 820px;">
            {{ lang._('Paste text to see what the detectors would find with the saved settings. Nothing is stored or logged and the text is deleted immediately.') }}
        </p>
        <textarea id="test-text" class="form-control" rows="8" style="max-width: 820px;"
                  placeholder="{{ lang._('For example: my card is 4111 1111 1111 1111') }}"></textarea>
        <br/>
        <button class="btn btn-default" id="testAct" type="button">{{ lang._('Scan') }}</button>
        <div id="test-result" style="margin-top: 12px; max-width: 900px;"></div>
    </div>
    <div class="col-md-12">
        <hr/>
        <button class="btn btn-primary" id="reconfigureAct"
                data-endpoint="/api/layer7security/service/reconfigure"
                data-label="{{ lang._('Apply') }}"
                data-error-title="{{ lang._('Error applying AI inspection') }}"
                type="button"></button>
        <br/><br/>
    </div>
</div>
