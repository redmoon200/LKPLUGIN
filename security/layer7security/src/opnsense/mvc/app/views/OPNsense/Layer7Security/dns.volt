<script>
    $(document).ready(function () {
        function esc(value) {
            return $('<div>').text(value === null || value === undefined ? '' : String(value)).html();
        }

        function loadStatus() {
            ajaxGet('/api/layer7security/dns/status', {}, function (d) {
                const body = $('#dns-lists tbody').empty();
                if (!d || !d.lists) { return; }
                d.lists.forEach(function (l) {
                    body.append('<tr><td>' + esc(l.category) + '</td><td>' + esc(l.seed) + '</td><td>' + esc(l.feed) +
                        '</td><td>' + (l.updated ? esc(new Date(l.updated * 1000).toLocaleString()) : '-') + '</td></tr>');
                });
            });
        }

        mapDataToFormUI({ 'frm_dns': '/api/layer7security/settings/get' }).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });
        loadStatus();

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function () {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/layer7security/settings/set", 'frm_dns', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
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

        $("#feedAct").click(function () {
            $("#feedAct_progress").addClass("fa fa-spinner fa-pulse");
            ajaxCall('/api/layer7security/dns/update', {}, function (data, status) {
                $("#feedAct_progress").removeClass("fa fa-spinner fa-pulse");
                let msg = data && data.message ? data.message : '';
                if (data && data.lists) {
                    msg = data.updated + ' / ' + data.total + ' {{ lang._("lists updated") }}';
                    data.lists.forEach(function (l) {
                        msg += '\n' + l.category + ': ' + (l.ok ? l.domains + ' domains' : l.error);
                    });
                }
                stdDialogInform("{{ lang._('Feed update') }}", $('<div>').text(msg).html().replace(/\n/g, '<br/>'), "{{ lang._('Close') }}");
                loadStatus();
            });
        });
    });
</script>

<div class="content-box">
    {{ partial("layout_partials/base_form", ['fields': dnsForm, 'id': 'frm_dns']) }}
    <div class="col-md-12">
        <hr/>
        <button class="btn btn-primary" id="reconfigureAct"
                data-endpoint="/api/layer7security/service/reconfigure"
                data-label="{{ lang._('Apply') }}"
                data-error-title="{{ lang._('Error applying DNS filter') }}"
                type="button"></button>
        <button class="btn btn-default" id="feedAct" type="button">
            <i id="feedAct_progress"></i> {{ lang._('Update lists now') }}
        </button>
        <br/><br/>
        <h3>{{ lang._('Category lists') }}</h3>
        <table class="table table-condensed table-striped" id="dns-lists" style="max-width: 640px;">
            <thead><tr><th>{{ lang._('Category') }}</th><th>{{ lang._('Seed domains') }}</th><th>{{ lang._('Feed domains') }}</th><th>{{ lang._('Last update') }}</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
</div>
