<script>
    $(document).ready(function () {
        function esc(value) {
            return $('<div>').text(value === null || value === undefined ? '' : String(value)).html();
        }

        mapDataToFormUI({ 'frm_audit': '/api/layer7security/settings/get' }).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });

        const grid = $("#grid-audit").UIBootgrid({
            search: '/api/layer7security/audit/search',
            options: {
                rowCount: [25, 50, 100, 250],
                requestHandler: function (request) {
                    request.period = $('#audit-period').val();
                    request.kind = $('#audit-kind').val();
                    return request;
                },
                formatters: {
                    time: function (column, row) { return esc(new Date(row.ts * 1000).toLocaleString()); },
                    hash: function (column, row) { return '<code title="' + esc(row.hash) + '">' + esc(String(row.hash).substr(0, 10)) + '</code>'; }
                }
            }
        });
        $('#audit-period, #audit-kind').on('change', function () { $("#grid-audit").bootgrid('reload'); });

        function loadStatus() {
            ajaxGet('/api/layer7security/audit/status', {}, function (d) {
                if (!d) { return; }
                $('#st-state').text(d.enabled ? "{{ lang._('enabled') }}" : "{{ lang._('disabled') }}");
                $('#st-records').text(d.records);
                $('#st-head').text(d.head ? String(d.head).substr(0, 16) + '...' : '-');
                $('#st-last').text(d.last ? new Date(d.last * 1000).toLocaleString() : '-');
                $('#st-syslog').text((d.syslogLocal ? "{{ lang._('local') }}" : '') + (d.syslogTarget ? ' ' + d.syslogTarget : '') || "{{ lang._('none') }}");
            });
        }
        loadStatus();

        function loadNotice() {
            ajaxGet('/api/layer7security/audit/notice', {}, function (d) {
                if (!d) { return; }
                $('#notice-text').text(d.notice + (d.custom ? '\n\n' + d.custom : ''));
                if (d.ackBy) {
                    $('#ack-state').html('<span class="label label-success">{{ lang._("acknowledged") }}</span> ' + esc(d.ackBy) + ', ' + esc(d.ackAt));
                    $('#ackAct').prop('disabled', true);
                } else {
                    $('#ack-state').html('<span class="label label-danger">{{ lang._("not acknowledged") }}</span>');
                }
            });
        }
        loadNotice();

        $('#ack-check').on('change', function () { $('#ackAct').prop('disabled', !this.checked || $('#ack-state .label-success').length > 0); });
        $('#ackAct').click(function () {
            ajaxCall('/api/layer7security/audit/ack', {}, function (data) {
                loadNotice();
                loadStatus();
                $("#grid-audit").bootgrid('reload');
            });
        });

        $('#verifyAct').click(function () {
            $('#verify-result').html('<i class="fa fa-spinner fa-pulse"></i>');
            ajaxCall('/api/layer7security/audit/verify', {}, function (d) {
                if (d && d.ok) {
                    $('#verify-result').html('<div class="alert alert-success">{{ lang._("The chain is intact") }}: ' + esc(d.records) +
                        ' {{ lang._("records verified, head") }} <code>' + esc(String(d.head || '').substr(0, 16)) + '...</code></div>');
                } else {
                    $('#verify-result').html('<div class="alert alert-danger"><strong>{{ lang._("Tampering detected") }}</strong> ' +
                        '{{ lang._("at record") }} ' + esc(d && d.bad_seq) + ': ' + esc(d && d.reason) + '</div>');
                }
                $("#grid-audit").bootgrid('reload');
            });
        });

        $('.exportAct').click(function () {
            window.location = '/api/layer7security/audit/export?format=' + encodeURIComponent($(this).data('format')) +
                '&period=' + encodeURIComponent($('#export-period').val());
        });

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function () {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/layer7security/audit/set", 'frm_audit', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
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
            }
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#log">{{ lang._('Log') }}</a></li>
    <li><a data-toggle="tab" href="#integrity">{{ lang._('Integrity and export') }}</a></li>
    <li><a data-toggle="tab" href="#privacy">{{ lang._('Privacy') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
</ul>
<div class="tab-content content-box">
    <div id="log" class="tab-pane fade in active">
        <div class="form-inline" style="margin: 10px 0;">
            <label for="audit-period">{{ lang._('Period') }}</label>
            <select id="audit-period" class="selectpicker" data-width="auto">
                <option value="3600">{{ lang._('Last hour') }}</option>
                <option value="86400" selected="selected">{{ lang._('Last 24 hours') }}</option>
                <option value="604800">{{ lang._('Last 7 days') }}</option>
                <option value="2592000">{{ lang._('Last 30 days') }}</option>
                <option value="31536000">{{ lang._('Last year') }}</option>
            </select>
            <label for="audit-kind">{{ lang._('Type') }}</label>
            <select id="audit-kind" class="selectpicker" data-width="auto">
                <option value="">{{ lang._('All') }}</option>
                <option value="ai-use">ai-use</option>
                <option value="ai-block">ai-block</option>
                <option value="dlp-detect">dlp-detect</option>
                <option value="dlp-block">dlp-block</option>
                <option value="audit-access">audit-access</option>
                <option value="audit-prune">audit-prune</option>
            </select>
        </div>
        <table id="grid-audit" class="table table-condensed table-hover table-striped" data-store-selection="false">
            <thead>
                <tr>
                    <th data-column-id="seq" data-type="numeric" data-width="5em" data-identifier="true">#</th>
                    <th data-column-id="ts" data-formatter="time" data-width="11em">{{ lang._('Time') }}</th>
                    <th data-column-id="kind" data-type="string" data-width="8em">{{ lang._('Type') }}</th>
                    <th data-column-id="action" data-type="string" data-width="7em">{{ lang._('Action') }}</th>
                    <th data-column-id="client" data-type="string">{{ lang._('Client') }}</th>
                    <th data-column-id="user" data-type="string">{{ lang._('User') }}</th>
                    <th data-column-id="service" data-type="string">{{ lang._('Service') }}</th>
                    <th data-column-id="category" data-type="string" data-width="7em">{{ lang._('Category') }}</th>
                    <th data-column-id="detail" data-type="string">{{ lang._('Detail (masked)') }}</th>
                    <th data-column-id="hash" data-formatter="hash" data-width="8em">{{ lang._('Hash') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
    <div id="integrity" class="tab-pane fade in">
        <table class="table table-condensed" style="max-width: 640px; margin-top: 10px;">
            <tr><th>{{ lang._('Audit log') }}</th><td id="st-state">-</td></tr>
            <tr><th>{{ lang._('Records') }}</th><td id="st-records">-</td></tr>
            <tr><th>{{ lang._('Chain head') }}</th><td><code id="st-head">-</code></td></tr>
            <tr><th>{{ lang._('Last record') }}</th><td id="st-last">-</td></tr>
            <tr><th>{{ lang._('Syslog') }}</th><td id="st-syslog">-</td></tr>
        </table>
        <button class="btn btn-primary" id="verifyAct" type="button"><span class="fa fa-check-circle"></span> {{ lang._('Verify the hash chain') }}</button>
        <div id="verify-result" style="margin-top: 12px; max-width: 760px;"></div>
        <hr/>
        <h3>{{ lang._('Export') }}</h3>
        <div class="form-inline">
            <select id="export-period" class="selectpicker" data-width="auto">
                <option value="86400">{{ lang._('Last 24 hours') }}</option>
                <option value="604800">{{ lang._('Last 7 days') }}</option>
                <option value="2592000" selected="selected">{{ lang._('Last 30 days') }}</option>
                <option value="31536000">{{ lang._('Last year') }}</option>
            </select>
            <button class="btn btn-default exportAct" data-format="csv" type="button"><span class="fa fa-download"></span> CSV</button>
            <button class="btn btn-default exportAct" data-format="json" type="button"><span class="fa fa-download"></span> JSON</button>
            <button class="btn btn-default exportAct" data-format="jsonl" type="button"><span class="fa fa-download"></span> JSON Lines</button>
        </div>
        <p class="text-muted" style="margin-top: 10px; max-width: 760px;">
            {{ lang._('Exports contain the previous-hash and hash of every record, so they can be verified offline. Exporting is recorded in the log.') }}
        </p>
    </div>
    <div id="privacy" class="tab-pane fade in">
        <div class="alert alert-warning" style="margin-top: 10px;">
            {{ lang._('Read this notice and make sure the people concerned have been informed before you enable the audit log or content inspection.') }}
        </div>
        <pre id="notice-text" style="white-space: pre-wrap; max-width: 900px;"></pre>
        <p><strong>{{ lang._('Status') }}:</strong> <span id="ack-state">-</span></p>
        <div class="checkbox">
            <label><input type="checkbox" id="ack-check"> {{ lang._('I confirm that the people whose traffic is affected have been informed about this monitoring as the law and our policies require.') }}</label>
        </div>
        <button class="btn btn-primary" id="ackAct" type="button" disabled="disabled">{{ lang._('Acknowledge the privacy notice') }}</button>
        <br/><br/>
    </div>
    <div id="settings" class="tab-pane fade in">
        {{ partial("layout_partials/base_form", ['fields': auditForm, 'id': 'frm_audit']) }}
    </div>
    <div class="col-md-12">
        <hr/>
        <button class="btn btn-primary" id="reconfigureAct"
                data-endpoint="/api/layer7security/service/reconfigure"
                data-label="{{ lang._('Apply') }}"
                data-error-title="{{ lang._('Error applying audit settings') }}"
                type="button"></button>
        <br/><br/>
    </div>
</div>
