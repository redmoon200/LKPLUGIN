<script>
    $(document).ready(function () {
        function esc(value) {
            return $('<div>').text(value === null || value === undefined ? '' : String(value)).html();
        }
        function bytes(n) {
            n = Number(n) || 0;
            const units = ['B', 'KB', 'MB', 'GB'];
            let i = 0;
            while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
            return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + ' ' + units[i];
        }

        mapDataToFormUI({ 'frm_ai': '/api/layer7security/settings/get' }).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });

        $("#grid-ai").UIBootgrid({
            search: '/api/layer7security/settings/search_ai',
            get: '/api/layer7security/settings/get_ai/',
            set: '/api/layer7security/settings/set_ai/',
            add: '/api/layer7security/settings/add_ai/',
            del: '/api/layer7security/settings/del_ai/',
            toggle: '/api/layer7security/settings/toggle_ai/'
        });

        function loadUsage() {
            ajaxGet('/api/layer7security/dashboard/ai', { period: $('#ai-period').val() }, function (d) {
                const sb = $('#tbl-ai-services tbody').empty();
                const cb = $('#tbl-ai-clients tbody').empty();
                if (!d || !d.services) { return; }
                if (d.services.length === 0) {
                    sb.append('<tr><td colspan="6" class="text-muted">{{ lang._("No AI traffic seen in this period.") }}</td></tr>');
                }
                d.services.forEach(function (r) {
                    sb.append('<tr><td>' + esc(r.name) + '</td><td>' + esc(r.clients) + '</td><td>' + esc(r.flows) +
                        '</td><td>' + bytes(r.down) + '</td><td>' + bytes(r.up) + '</td><td>' +
                        (r.blocked > 0 ? '<span class="label label-danger">' + esc(r.blocked) + '</span>' : '0') + '</td></tr>');
                });
                d.clients.forEach(function (r) {
                    cb.append('<tr><td>' + esc(r.client) + '</td><td>' + esc(r.name) + '</td><td>' + esc(r.flows) +
                        '</td><td>' + bytes(r.down + r.up) + '</td><td>' +
                        (r.blocked > 0 ? '<span class="label label-danger">{{ lang._("blocked") }}</span>' : '<span class="label label-default">{{ lang._("seen") }}</span>') +
                        '</td><td>' + esc(new Date(r.last * 1000).toLocaleString()) + '</td></tr>');
                });
            });
        }
        loadUsage();
        $('#ai-period').on('change', loadUsage);
        $('#aiRefresh').click(loadUsage);

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function () {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/layer7security/settings/set", 'frm_ai', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
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
                loadUsage();
            }
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#usage">{{ lang._('Usage') }}</a></li>
    <li><a data-toggle="tab" href="#rules">{{ lang._('Rules') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
</ul>
<div class="tab-content content-box">
    <div id="usage" class="tab-pane fade in active">
        <div class="form-inline" style="margin: 10px 0;">
            <label for="ai-period">{{ lang._('Period') }}</label>
            <select id="ai-period" class="selectpicker" data-width="auto">
                <option value="3600">{{ lang._('Last hour') }}</option>
                <option value="86400" selected="selected">{{ lang._('Last 24 hours') }}</option>
                <option value="604800">{{ lang._('Last 7 days') }}</option>
            </select>
            <button class="btn btn-default" id="aiRefresh" type="button"><span class="fa fa-refresh"></span> {{ lang._('Refresh') }}</button>
        </div>
        <h3>{{ lang._('AI services in use') }}</h3>
        <table class="table table-condensed table-striped" id="tbl-ai-services">
            <thead><tr><th>{{ lang._('Service') }}</th><th>{{ lang._('Clients') }}</th><th>{{ lang._('Flows') }}</th><th>{{ lang._('Down') }}</th><th>{{ lang._('Up') }}</th><th>{{ lang._('Blocked') }}</th></tr></thead>
            <tbody></tbody>
        </table>
        <h3>{{ lang._('Who uses what') }}</h3>
        <table class="table table-condensed table-striped" id="tbl-ai-clients">
            <thead><tr><th>{{ lang._('Client') }}</th><th>{{ lang._('Service') }}</th><th>{{ lang._('Flows') }}</th><th>{{ lang._('Volume') }}</th><th>{{ lang._('Result') }}</th><th>{{ lang._('Last seen') }}</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
    <div id="rules" class="tab-pane fade in">
        <table id="grid-ai" class="table table-condensed table-hover table-striped" data-editDialog="DialogAi" data-editAlert="aiChangeMessage">
            <thead>
                <tr>
                    <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                    <th data-column-id="service" data-type="string">{{ lang._('Service') }}</th>
                    <th data-column-id="action" data-width="8em" data-type="string">{{ lang._('Action') }}</th>
                    <th data-column-id="inspect" data-width="7em" data-type="boolean" data-formatter="boolean">{{ lang._('Inspect') }}</th>
                    <th data-column-id="sources" data-type="string">{{ lang._('Sources') }}</th>
                    <th data-column-id="users" data-type="string">{{ lang._('Users') }}</th>
                    <th data-column-id="startTime" data-width="6em" data-type="string">{{ lang._('From') }}</th>
                    <th data-column-id="endTime" data-width="6em" data-type="string">{{ lang._('To') }}</th>
                    <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot>
                <tr>
                    <td></td>
                    <td>
                        <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-fw fa-plus"></span></button>
                        <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-fw fa-trash-o"></span></button>
                    </td>
                </tr>
            </tfoot>
        </table>
        <div id="aiChangeMessage" class="alert alert-info" style="display: none" role="alert">
            {{ lang._('After changing rules, click Apply so the engine and firewall pick them up.') }}
        </div>
    </div>
    <div id="settings" class="tab-pane fade in">
        {{ partial("layout_partials/base_form", ['fields': aiForm, 'id': 'frm_ai']) }}
    </div>
    <div class="col-md-12">
        <hr/>
        <button class="btn btn-primary" id="reconfigureAct"
                data-endpoint="/api/layer7security/service/reconfigure"
                data-label="{{ lang._('Apply') }}"
                data-error-title="{{ lang._('Error applying AI service rules') }}"
                type="button"></button>
        <br/><br/>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogAi, 'id': 'DialogAi', 'label': lang._('Edit AI service rule')]) }}
