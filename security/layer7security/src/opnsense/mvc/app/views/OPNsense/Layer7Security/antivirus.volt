<script>
    $(document).ready(function () {
        function esc(value) {
            return $('<div>').text(value === null || value === undefined ? '' : String(value)).html();
        }

        mapDataToFormUI({ 'frm_antivirus': '/api/layer7security/settings/get' }).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });

        $("#grid-av").UIBootgrid({
            search: '/api/layer7security/antivirus/search',
            options: {
                rowCount: [25, 50, 100, 250],
                requestHandler: function (request) {
                    request.period = $('#av-period').val();
                    return request;
                },
                formatters: {
                    time: function (column, row) { return esc(new Date(row.ts * 1000).toLocaleString()); },
                    action: function (column, row) {
                        return row.action === 'blocked' ? '<span class="label label-danger">{{ lang._("blocked") }}</span>'
                                                         : '<span class="label label-info">{{ lang._("logged") }}</span>';
                    },
                    hash: function (column, row) {
                        return row.sha256 ? '<code title="' + esc(row.sha256) + '">' + esc(String(row.sha256).substr(0, 12)) + '</code>' : '';
                    }
                }
            }
        });
        $('#av-period').on('change', function () { $("#grid-av").bootgrid('reload'); });

        function loadStatus() {
            ajaxGet('/api/layer7security/antivirus/status', {}, function (d) {
                if (!d) { return; }
                const s = d.icapStats || {};
                $('#st-proxy').html(d.running ? '<span class="label label-success">{{ lang._("running") }}</span>' : '<span class="label label-default">{{ lang._("stopped") }}</span>');
                $('#st-hashes').text(d.hashes === undefined ? '-' : d.hashes);
                $('#st-feed').text(d.feedTs ? new Date(d.feedTs * 1000).toLocaleString() + ' (' + d.feedCount + ')' : "{{ lang._('never') }}");
                $('#st-feederr').text(d.feedError || '');
                $('#st-det').text(d.detections24h === undefined ? '-' : d.detections24h);
                $('#st-blk').text(d.blocked24h === undefined ? '-' : d.blocked24h);
            });
        }
        loadStatus();
        setInterval(loadStatus, 15000);

        $('#feedAct').click(function () {
            $('#feed-result').html('<i class="fa fa-spinner fa-pulse"></i>');
            ajaxCall('/api/layer7security/antivirus/feed_update', {}, function (d) {
                if (d && d.updated) {
                    $('#feed-result').html('<span class="text-success">' + esc("{{ lang._('Updated:') }} " + d.count + " {{ lang._('hashes') }}") + '</span>');
                } else {
                    $('#feed-result').html('<span class="text-danger">' + esc((d && d.error) || "{{ lang._('Nothing was updated.') }}") + '</span>');
                }
                loadStatus();
            });
        });

        $('#checkAct').click(function () {
            $('#check-result').html('<i class="fa fa-spinner fa-pulse"></i>');
            ajaxCall('/api/layer7security/antivirus/check', { sha256: $('#check-hash').val() }, function (d) {
                if (!d) { return; }
                if (d.error) { $('#check-result').html('<span class="text-danger">' + esc(d.error) + '</span>'); return; }
                $('#check-result').html(d.known
                    ? '<span class="text-danger"><strong>{{ lang._("Known:") }}</strong> ' + (d.eicar ? "{{ lang._('this is the EICAR test file.') }}" : "{{ lang._('this hash is in the blocklist.') }}") + '</span>'
                    : '<span class="text-success">{{ lang._("Not in the blocklist.") }}</span>');
            });
        });

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function () {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/layer7security/settings/set", 'frm_antivirus', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
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
                $("#grid-av").bootgrid('reload');
            }
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#detections">{{ lang._('Detections') }}</a></li>
    <li><a data-toggle="tab" href="#status">{{ lang._('Status and feed') }}</a></li>
</ul>
<div class="tab-content content-box">
    <div id="settings" class="tab-pane fade in active">
        <div class="alert alert-info" style="margin: 10px;">
            {{ lang._('This is download protection, not a signature-based virus scanner. It blocks files whose SHA-256 is in a malware feed or your own list (and the EICAR test file), and it can log or block risky file types. Content is only looked at after the file has been downloaded through the firewall; HTTPS downloads are only checked for the sites you list below, which are decrypted with the inspection CA (the privacy notice must be acknowledged first).') }}
        </div>
        {{ partial("layout_partials/base_form", ['fields': antivirusForm, 'id': 'frm_antivirus']) }}
    </div>
    <div id="detections" class="tab-pane fade in">
        <div style="margin: 10px 0;">
            <select id="av-period" class="selectpicker" data-width="auto">
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
                    <th data-column-id="action" data-formatter="action" data-width="6em">{{ lang._('Action') }}</th>
                    <th data-column-id="client" data-type="string">{{ lang._('Client') }}</th>
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
    <div id="status" class="tab-pane fade in">
        <table class="table table-condensed" style="max-width: 640px; margin-top: 10px;">
            <tr><th>{{ lang._('Inspection proxy') }}</th><td id="st-proxy">-</td></tr>
            <tr><th>{{ lang._('Hashes known') }}</th><td id="st-hashes">-</td></tr>
            <tr><th>{{ lang._('Feed last updated') }}</th><td><span id="st-feed">-</span> <span id="st-feederr" class="text-danger"></span></td></tr>
            <tr><th>{{ lang._('Detections, last 24 h') }}</th><td id="st-det">-</td></tr>
            <tr><th>{{ lang._('Blocked, last 24 h') }}</th><td id="st-blk">-</td></tr>
        </table>
        <button class="btn btn-default" id="feedAct" type="button"><span class="fa fa-refresh"></span> {{ lang._('Update the feed now') }}</button>
        <span id="feed-result" style="margin-left: 10px;"></span>
        <h3>{{ lang._('Look up a hash') }}</h3>
        <div class="form-inline">
            <input type="text" id="check-hash" class="form-control" style="width: 36em;" placeholder="SHA-256"/>
            <button class="btn btn-default" id="checkAct" type="button">{{ lang._('Check') }}</button>
            <span id="check-result" style="margin-left: 10px;"></span>
        </div>
        <h3>{{ lang._('Testing it') }}</h3>
        <p style="max-width: 760px;">
            {{ lang._('Download the harmless EICAR test file (eicar.com.txt, from eicar.org or any mirror) over plain HTTP from a client behind the firewall. With "Known malware hashes" set to block, the download is replaced by a block page and a detection appears under Detections.') }}
        </p>
    </div>
    <div class="col-md-12">
        <hr/>
        <button class="btn btn-primary" id="reconfigureAct"
                data-endpoint="/api/layer7security/service/reconfigure"
                data-label="{{ lang._('Apply') }}"
                data-error-title="{{ lang._('Error applying download protection') }}"
                type="button"></button>
        <br/><br/>
    </div>
</div>
